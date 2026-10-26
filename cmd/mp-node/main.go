// mp-node runs a storage node, or a bridge node with -bridge-mirror.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/bridge"
	"mediapool/internal/node"
)

func main() {
	var cfg node.Config
	listen := flag.String("listen", ":7100", "listen address")
	poolPath := flag.String("pool", "pool.json", "pool membership file")
	keyPath := flag.String("key", "", "node private key (default <data>/node.key)")
	flag.StringVar(&cfg.ID, "id", "", "node id, as registered in the pool file")
	flag.StringVar(&cfg.Addr, "addr", "", "public URL other nodes reach this node at (default http://127.0.0.1<listen>)")
	flag.StringVar(&cfg.DataDir, "data", "", "shard directory")
	flag.StringVar(&cfg.CoordURL, "coord", "http://127.0.0.1:7000", "coordinator URL")
	flag.DurationVar(&cfg.Heartbeat, "heartbeat", 15*time.Second, "heartbeat interval")
	mirror := flag.String("bridge-mirror", "", "act as a bridge, serving torrent sources from this directory (<dir>/<infohash>/<file>)")
	flag.Parse()
	cfg.Logf = log.Printf
	if cfg.Addr == "" {
		cfg.Addr = "http://127.0.0.1" + *listen
	}
	if *keyPath == "" {
		*keyPath = filepath.Join(cfg.DataDir, "node.key")
	}
	var err error
	if cfg.Pool, err = auth.LoadPool(*poolPath); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatal(err)
	}
	if cfg.Key, err = auth.LoadOrCreateKey(*keyPath); err != nil {
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go n.Run(ctx)
	srv := &http.Server{Addr: *listen, Handler: n.Handler()}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("node %s on %s (bridge=%v)", cfg.ID, cfg.Addr, n.IsBridge())
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
