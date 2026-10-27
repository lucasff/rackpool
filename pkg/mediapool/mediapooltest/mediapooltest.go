// Package mediapooltest runs a complete pool in-process for tests of code
// built on pkg/mediapool: a coordinator and storage nodes on httptest
// servers, with a pool file and member keys written to a temp directory.
package mediapooltest

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/codec"
	"mediapool/internal/coord"
	"mediapool/internal/node"
	"mediapool/pkg/mediapool"
)

// Secret is the pool secret of every test pool.
const Secret = "mediapooltest-secret"

// Members can use the pool; each has a key file in the pool directory.
var Members = []string{"alice", "bob"}

type Pool struct {
	URL      string // coordinator base URL
	Dir      string // holds pool.json and <member>.key
	PoolFile string
	Nodes    []*node.Node
}

// Start runs a coordinator and n storage nodes (each run by its own member,
// so each is its own failure domain) until the test ends. Erasure coding is
// K=4 with up to 12 shards, so n should be at least 12.
func Start(t testing.TB, n int) *Pool {
	t.Helper()
	return StartWith(t, n, Options{K: 4, MaxN: 12, AnchoredN: 6, OrphanN: 9, SegmentSize: 64 << 10})
}

// Options sets the pool's erasure code and segment size.
type Options struct {
	K, MaxN, AnchoredN, OrphanN int
	SegmentSize                 int
}

// StartWith is Start with explicit pool parameters; n must be at least
// opt.OrphanN.
func StartWith(t testing.TB, n int, opt Options) *Pool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &Pool{Dir: t.TempDir()}
	p.PoolFile = filepath.Join(p.Dir, "pool.json")

	coordKey := auth.Generate()
	pool := &auth.Pool{Coordinator: auth.PubHex(coordKey)}
	for _, m := range Members {
		k := auth.Generate()
		writeFile(t, filepath.Join(p.Dir, m+".key"), []byte(hex.EncodeToString(k.Seed())+"\n"))
		pool.Members = append(pool.Members, auth.Member{Name: m, Key: auth.PubHex(k)})
	}

	type pending struct {
		h   *deferredHandler
		srv *httptest.Server
		key ed25519.PrivateKey
		id  string
	}
	var ps []pending
	for i := range n {
		owner := fmt.Sprintf("op%02d", i)
		ownerKey := auth.Generate()
		pool.Members = append(pool.Members, auth.Member{Name: owner, Key: auth.PubHex(ownerKey)})
		id, key := fmt.Sprintf("n%02d", i), auth.Generate()
		pool.Nodes = append(pool.Nodes, auth.NodeEntry{ID: id, Key: auth.PubHex(key), Owner: owner})
		h := &deferredHandler{}
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		ps = append(ps, pending{h, srv, key, id})
	}
	if err := pool.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(pool, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p.PoolFile, b)

	cfg := coord.DefaultConfig()
	cfg.Params = codec.Params{K: opt.K, MaxN: opt.MaxN}
	cfg.SegmentSize = opt.SegmentSize
	cfg.AnchoredN, cfg.OrphanN = opt.AnchoredN, opt.OrphanN
	cfg.TargetLoss = 0
	cfg.RepairSlack, cfg.ShrinkSlack = 1, 1
	cfg.HotReadsPerShard = 1e9
	cfg.TickEvery = 200 * time.Millisecond
	cfg.GCGrace = time.Hour
	cfg.Key, cfg.Pool, cfg.Fresh = coordKey, pool.Clone(), true // each process attaches its own catalog
	cfg.LogPath = filepath.Join(t.TempDir(), "coord.log")
	co, err := coord.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { co.Close() })
	srv := httptest.NewServer(co.Handler())
	t.Cleanup(srv.Close)
	p.URL = srv.URL
	stop := make(chan struct{})
	go co.Run(stop)
	t.Cleanup(func() { close(stop) })

	for _, pd := range ps {
		nd, err := node.New(node.Config{
			ID: pd.id, Addr: pd.srv.URL, DataDir: t.TempDir(), CoordURL: p.URL,
			Heartbeat: 500 * time.Millisecond, Key: pd.key, Pool: pool.Clone(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { nd.Close() })
		pd.h.h = nd.Handler()
		p.Nodes = append(p.Nodes, nd)
		if err := nd.HeartbeatOnce(ctx); err != nil {
			t.Fatal(err)
		}
		go nd.Run(ctx)
	}
	return p
}

// Config returns a client config for one of Members.
func (p *Pool) Config(member string) mediapool.Config {
	return mediapool.Config{
		CoordURL: p.URL, PoolFile: p.PoolFile, Member: member,
		KeyFile: filepath.Join(p.Dir, member+".key"), Secret: Secret,
	}
}

func writeFile(t testing.TB, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// deferredHandler lets a node learn its own server URL before it exists.
type deferredHandler struct{ h http.Handler }

func (d *deferredHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) { d.h.ServeHTTP(w, r) }
