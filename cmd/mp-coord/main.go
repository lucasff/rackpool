// mp-coord runs a pool coordinator.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"mediapool/internal/auth"
	"mediapool/internal/coord"
	"mediapool/internal/envflag"
	"mediapool/internal/limits"
	"mediapool/internal/relay"
)

func main() {
	cfg := coord.DefaultConfig()
	listen := flag.String("listen", ":7000", "listen address")
	poolPath := flag.String("pool", "pool.json", "pool membership file")
	keyPath := flag.String("key", "coord.key", "coordinator private key")
	flag.StringVar(&cfg.LogPath, "catalog", "catalog.log", "catalog log file")
	flag.BoolVar(&cfg.Fresh, "fresh", false, "start a new pool (otherwise an empty catalog is recovered from nodes)")
	flag.IntVar(&cfg.Params.K, "k", cfg.Params.K, "data shards per segment")
	flag.IntVar(&cfg.Params.MaxN, "max-n", cfg.Params.MaxN, "total shard indices per segment (cap for hot expansion)")
	flag.IntVar(&cfg.AnchoredN, "anchored-n", cfg.AnchoredN, "shards for segments with a verified external swarm")
	flag.IntVar(&cfg.OrphanN, "orphan-n", cfg.OrphanN, "shards for segments without one")
	flag.Float64Var(&cfg.TargetLoss, "target-loss", cfg.TargetLoss, "size segments by estimated loss probability from holder reliability (0 = fixed floors)")
	flag.Float64Var(&cfg.AnchoredTargetLoss, "anchored-target-loss", cfg.AnchoredTargetLoss, "loss target for segments backed by a verified swarm")
	flag.IntVar(&cfg.MinN, "min-n", cfg.MinN, "fewest shards a segment may have in loss-target mode")
	flag.StringVar(&cfg.ScoresPath, "scores", "scores.json", "reliability scores file")
	flag.IntVar(&cfg.RepairSlack, "repair-slack", cfg.RepairSlack, "repair once this many shards below the floor")
	flag.Float64Var(&cfg.HotReadsPerShard, "hot-reads-per-shard", cfg.HotReadsPerShard, "reads/min that earn one extra shard")
	flag.DurationVar(&cfg.OfflineAfter, "offline-after", cfg.OfflineAfter, "heartbeat silence before a node stops serving reads")
	flag.DurationVar(&cfg.DownAfter, "down-after", cfg.DownAfter, "heartbeat silence before a node's shards are rebuilt elsewhere")
	flag.DurationVar(&cfg.SwarmCheckEvery, "swarm-check-every", cfg.SwarmCheckEvery, "how often bridges re-check external swarms")
	flag.DurationVar(&cfg.GCGrace, "gc-grace", cfg.GCGrace, "how long a segment sits unreferenced before collection")
	flag.DurationVar(&cfg.TickEvery, "tick", cfg.TickEvery, "scheduler interval")
	relayOn := flag.Bool("relay", true, "relay traffic for nodes that can't be reached directly (behind CGNAT)")
	var relayLimit limits.Rate
	flag.Var(&relayLimit, "relay-limit", "bandwidth cap per relayed node, e.g. 20M for 20 Mbit/s (0 = unlimited)")
	pubkey := flag.Bool("print-pubkey", false, "print the coordinator's public key (creating the key if needed) and exit")
	if err := envflag.Parse(flag.CommandLine, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
	cfg.Logf = log.Printf
	cfg.Reliability.OfflineAfter = cfg.OfflineAfter

	var err error
	if cfg.Key, err = auth.LoadOrCreateKey(*keyPath); err != nil {
		log.Fatal(err)
	}
	if *pubkey {
		fmt.Println(auth.PubHex(cfg.Key))
		return
	}
	pool, err := auth.LoadPool(*poolPath)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Pool = pool
	c, err := coord.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	go c.Run(make(chan struct{}))
	mux := http.NewServeMux()
	mux.Handle("/v1/", c.Handler())
	if *relayOn {
		rs := &relay.Server{Pool: pool, PerNodeBps: relayLimit.BytesPerSec(), Logf: log.Printf}
		mux.Handle("/v1/relay/", rs)
		mux.Handle("/relay/", rs)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	log.Printf("coordinator on %s (k=%d anchored=%d orphan=%d max=%d, %d members, %d nodes)",
		*listen, cfg.Params.K, cfg.AnchoredN, cfg.OrphanN, cfg.Params.MaxN, len(pool.Members), len(pool.Nodes))
	log.Fatal(http.ListenAndServe(*listen, mux))
}
