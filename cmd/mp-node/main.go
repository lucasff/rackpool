// mp-node runs a storage node, or a bridge node with -bridge-mirror.
//
// Every flag can also be set as an MP_* environment variable, e.g.
// MP_QUOTA=2T MP_UPLOAD_LIMIT=50M.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/bridge"
	"mediapool/internal/client"
	"mediapool/internal/envflag"
	"mediapool/internal/limits"
	"mediapool/internal/node"
	"mediapool/internal/rc"
	"mediapool/internal/vfs"
)

func main() {
	var cfg node.Config
	var quota, reserve limits.Bytes
	var upload, download limits.Rate
	reserve = 10e9
	listen := flag.String("listen", ":7100", "listen address")
	poolPath := flag.String("pool", "pool.json", "pool membership file")
	keyPath := flag.String("key", "", "node private key (default <data>/node.key, created if missing)")
	flag.StringVar(&cfg.ID, "id", "", "node id, as registered in the pool file")
	flag.StringVar(&cfg.Addr, "addr", "", "URL other members reach this node at, if you've set one up (port forward, DNS name, reverse proxy); checked by dial-back")
	var ro node.ReachOptions
	flag.StringVar(&ro.Mode, "reach", "auto", "how to be reachable: auto (direct if it works, else relay), direct, relay, or off (advertise -addr unchecked)")
	flag.BoolVar(&ro.PortMap, "port-map", true, "ask the router to forward the port automatically (UPnP/NAT-PMP; in Docker this needs host networking)")
	flag.StringVar(&ro.RelayURL, "relay", "", "relay to use when not directly reachable (default: the coordinator)")
	flag.StringVar(&cfg.DataDir, "data", "", "shard directory")
	flag.StringVar(&cfg.CoordURL, "coord", "http://127.0.0.1:7000", "coordinator URL")
	flag.DurationVar(&cfg.Heartbeat, "heartbeat", 15*time.Second, "heartbeat interval")
	flag.Var(&quota, "quota", "most disk to give the pool, e.g. 500G or 2T (0 = whatever is free above -reserve)")
	flag.Var(&reserve, "reserve", "free disk space to always leave alone")
	flag.Var(&upload, "upload-limit", "upload cap, e.g. 50M for 50 Mbit/s (0 = unlimited)")
	flag.Var(&download, "download-limit", "download cap, e.g. 200M (0 = unlimited)")
	flag.IntVar(&cfg.MaxTransfers, "max-transfers", 16, "concurrent shard transfers")
	flag.BoolVar(&cfg.Drain, "drain", false, "move all shards to other nodes, then hold nothing (to leave the pool or free the disk)")
	mirror := flag.String("bridge-mirror", "", "act as a bridge, serving torrent sources from this directory (<dir>/<infohash>/<file>)")
	rcAddr := flag.String("rc-addr", "", "serve the rc API and web UI here, e.g. 127.0.0.1:5572 (off by default)")
	rcUser := flag.String("rc-user", "", "rc basic-auth user (required unless -rc-addr is loopback)")
	rcPass := flag.String("rc-pass", "", "rc basic-auth password")
	rcMember := flag.String("rc-member", "", "also show the library in the web UI, as this member (needs -rc-member-key and MEDIAPOOL_SECRET)")
	rcMemberKey := flag.String("rc-member-key", "", "that member's private key file")
	pubkey := flag.Bool("print-pubkey", false, "print this node's public key (creating the key if needed) and exit")
	if err := envflag.Parse(flag.CommandLine, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
	cfg.Logf = log.Printf
	cfg.Quota, cfg.Reserve = int64(quota), int64(reserve)
	cfg.UploadBps, cfg.DownloadBps = upload.BytesPerSec(), download.BytesPerSec()
	if cfg.DataDir == "" {
		log.Fatal("-data (MP_DATA) is required")
	}
	if *keyPath == "" {
		*keyPath = filepath.Join(cfg.DataDir, "node.key")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatal(err)
	}
	key, err := auth.LoadOrCreateKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	if *pubkey {
		fmt.Println(auth.PubHex(key))
		return
	}
	cfg.Key = key
	ro.Announce, ro.ListenPort = cfg.Addr, node.PortOf(*listen)
	if ro.RelayURL == "" {
		ro.RelayURL = cfg.CoordURL
	}
	if cfg.Addr == "" {
		cfg.Addr = "http://127.0.0.1" + *listen // placeholder until reachability is established
	}
	if cfg.Pool, err = auth.LoadPool(*poolPath); err != nil {
		log.Fatal(err)
	}
	if *mirror != "" {
		cfg.Source = &bridge.Mirror{Dir: *mirror}
		cfg.PoolSecret = []byte(os.Getenv("MEDIAPOOL_SECRET"))
	}

	n, err := node.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer n.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *rcAddr != "" {
		if err := startRC(ctx, n, *rcAddr, *rcUser, *rcPass, *rcMember, *rcMemberKey, cfg); err != nil {
			log.Fatal(err)
		}
	}
	go n.RunReachability(ctx, ro)
	go n.Run(ctx)
	mux := http.NewServeMux()
	mux.Handle("/v1/", n.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	srv := &http.Server{Addr: *listen, Handler: mux}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	c := n.Capacity()
	log.Printf("node %s on %s (bridge=%v) quota=%s reserve=%s offering=%s up=%s down=%s drain=%v",
		cfg.ID, cfg.Addr, n.IsBridge(), limits.FormatBytes(cfg.Quota), limits.FormatBytes(cfg.Reserve),
		limits.FormatBytes(c.Free), upload.String(), download.String(), cfg.Drain)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func startRC(ctx context.Context, n *node.Node, addr, user, pass, member, memberKey string, cfg node.Config) error {
	host, _, _ := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); user == "" && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("-rc-addr %s is not loopback: set -rc-user/-rc-pass", addr)
	}
	s := &rc.Server{Node: n, User: user, Pass: pass, WebGUI: true}
	if member != "" {
		key, err := auth.LoadOrCreateKey(memberKey)
		if err != nil {
			return err
		}
		secret := os.Getenv("MEDIAPOOL_SECRET")
		if secret == "" {
			return fmt.Errorf("-rc-member needs MEDIAPOOL_SECRET")
		}
		c, err := client.New(cfg.CoordURL, []byte(secret), member, key, cfg.Pool, "")
		if err != nil {
			return err
		}
		s.FS = vfs.New(c)
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 30 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("rc: %v", err)
		}
	}()
	log.Printf("rc and web UI on http://%s", addr)
	return nil
}
