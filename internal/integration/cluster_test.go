package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/bridge"
	"mediapool/internal/client"
	"mediapool/internal/codec"
	"mediapool/internal/coord"
	"mediapool/internal/node"
	"mediapool/internal/proto"
	"mediapool/internal/relay"
	"mediapool/internal/reliability"
)

var secret = []byte("test-pool-secret")

type cluster struct {
	t         *testing.T
	ctx       context.Context
	pool      *auth.Pool
	coordKey  ed25519.PrivateKey
	cfg       coord.Config
	coord     *coord.Coordinator
	url       string
	nodes     []*node.Node
	direct    map[*node.Node]*deferredHandler
	relay     *relay.Server
	coordPool *auth.Pool
	paused    map[*node.Node]bool
	mirror    *bridge.Mirror
	members   map[string]ed25519.PrivateKey
	client    *client.Client // member "alice"
}

// newCluster starts a coordinator and n storage nodes, each run by its own
// member (so each is its own failure domain); the last node is a bridge.
// Everything talks real HTTP, and timings are shrunk so churn plays out in
// seconds.
func newCluster(t *testing.T, n int, tune func(*coord.Config)) *cluster {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &cluster{
		t: t, ctx: ctx, coordKey: auth.Generate(), paused: map[*node.Node]bool{}, direct: map[*node.Node]*deferredHandler{},
		mirror: &bridge.Mirror{Dir: t.TempDir()}, members: map[string]ed25519.PrivateKey{},
	}
	c.pool = &auth.Pool{Coordinator: auth.PubHex(c.coordKey)}
	addMember := func(name string) {
		k := auth.Generate()
		c.members[name] = k
		c.pool.Members = append(c.pool.Members, auth.Member{Name: name, Key: auth.PubHex(k)})
	}
	addMember("alice")
	c.pool.Members[0].Admin = true
	addMember("bob")
	addMember("mallory")

	type pending struct {
		h   *deferredHandler
		srv *httptest.Server
		key ed25519.PrivateKey
		id  string
	}
	var ps []pending
	for i := range n {
		owner := fmt.Sprintf("op%02d", i)
		addMember(owner)
		id := fmt.Sprintf("n%02d", i)
		key := auth.Generate()
		entry := auth.NodeEntry{ID: id, Key: auth.PubHex(key), Owner: owner}
		if i == n-1 {
			id = "bridge"
			entry.ID, entry.Bridge = id, true
		}
		c.pool.Nodes = append(c.pool.Nodes, entry)
		h := &deferredHandler{}
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		ps = append(ps, pending{h, srv, key, id})
	}
	if err := c.pool.Validate(); err != nil {
		t.Fatal(err)
	}

	cfg := coord.DefaultConfig()
	cfg.Params = codec.Params{K: 4, MaxN: 12}
	cfg.SegmentSize = 64 << 10
	cfg.AnchoredN, cfg.OrphanN = 6, 9
	cfg.TargetLoss = 0 // fixed floors; reliability mode has its own test
	cfg.RepairSlack, cfg.ShrinkSlack = 1, 1
	cfg.HotReadsPerShard = 1e9 // no heat unless a test asks for it
	cfg.HeatTau = 2 * time.Second
	cfg.OfflineAfter, cfg.DownAfter = 400*time.Millisecond, 1200*time.Millisecond
	cfg.TaskTimeout = 5 * time.Second
	cfg.SwarmCheckEvery = 300 * time.Millisecond
	cfg.ProofsPerTick = 50
	cfg.GCGrace = time.Hour
	cfg.Key, cfg.Pool, cfg.Fresh = c.coordKey, c.pool, true
	cfg.LogPath = filepath.Join(t.TempDir(), "coord.log")
	cfg.Logf = t.Logf
	if tune != nil {
		tune(&cfg)
	}
	c.cfg = cfg
	c.startCoord(cfg)

	for _, p := range ps {
		ncfg := node.Config{
			ID: p.id, Addr: p.srv.URL, DataDir: t.TempDir(), CoordURL: c.url,
			Key: p.key, Pool: c.pool.Clone(), Logf: t.Logf,
		}
		if p.id == "bridge" {
			ncfg.Source, ncfg.PoolSecret = c.mirror, secret
		}
		nd, err := node.New(ncfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { nd.Close() })
		p.h.h = nd.Handler()
		c.direct[nd] = p.h
		c.nodes = append(c.nodes, nd)
	}
	c.client = c.newClient("alice")
	c.heartbeat()
	return c
}

func (c *cluster) startCoord(cfg coord.Config) {
	c.t.Helper()
	cfg.Pool = c.pool.Clone() // each process attaches its own catalog
	c.coordPool = cfg.Pool
	co, err := coord.New(cfg)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { co.Close() })
	c.relay = &relay.Server{Pool: cfg.Pool, Logf: c.t.Logf}
	mux := http.NewServeMux()
	mux.Handle("/v1/relay/", c.relay)
	mux.Handle("/relay/", c.relay)
	mux.Handle("/", co.Handler())
	srv := httptest.NewServer(mux)
	c.t.Cleanup(srv.Close)
	c.coord, c.url = co, srv.URL
	for _, n := range c.nodes {
		n.SetCoordURL(srv.URL)
	}
}

func (c *cluster) newClient(member string) *client.Client {
	c.t.Helper()
	cl, err := client.New(c.url, secret, member, c.members[member], c.pool.Clone(), "")
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { cl.Close() })
	return cl
}

// deferredHandler lets a node learn its own server URL before it exists.
// Setting blocked makes the node's direct address refuse everything, as if
// it sat behind CGNAT.
type deferredHandler struct {
	h       http.Handler
	blocked atomic.Bool
}

func (d *deferredHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d.blocked.Load() {
		http.Error(w, "unreachable", http.StatusServiceUnavailable)
		return
	}
	d.h.ServeHTTP(w, r)
}

func (c *cluster) heartbeat() {
	for _, n := range c.nodes {
		if !c.paused[n] {
			_ = n.HeartbeatOnce(c.ctx)
		}
	}
}

func (c *cluster) cycle(times int) {
	for range times {
		c.heartbeat()
		c.coord.Tick()
		time.Sleep(20 * time.Millisecond)
	}
}

// settle runs heartbeats and scheduler ticks until cond holds for the first
// live segment.
func (c *cluster) settle(what string, timeout time.Duration, cond func(proto.SegmentStatus) bool) proto.SegmentStatus {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c.heartbeat()
		c.coord.Tick()
		st := c.coord.Status()
		if len(st.Segments) > 0 && cond(st.Segments[0]) {
			return st.Segments[0]
		}
		if time.Now().After(deadline) {
			for _, n := range st.Nodes {
				c.t.Logf("node %s online=%v shards=%d strikes=%d", n.ID, n.Online, n.Shards, n.Strikes)
			}
			c.t.Fatalf("timed out waiting for %s; last status %+v", what, st.Segments)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (c *cluster) pause(n *node.Node)  { c.paused[n] = true; n.SetPaused(true) }
func (c *cluster) resume(n *node.Node) { delete(c.paused, n); n.SetPaused(false) }

func randomFile(t *testing.T, size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (c *cluster) readBack(cl *client.Client, path string) []byte {
	c.t.Helper()
	m, err := cl.Stat(c.ctx, path)
	if err != nil {
		c.t.Fatal(err)
	}
	got, err := io.ReadAll(cl.Open(c.ctx, m))
	if err != nil {
		c.t.Fatalf("read %s: %v", path, err)
	}
	return got
}

func (c *cluster) holders(seg string) []*node.Node {
	var out []*node.Node
	for _, n := range c.nodes {
		inv, _ := n.Inventory()
		for _, k := range inv {
			if k.Segment == seg {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

func (c *cluster) shardCount() int {
	total := 0
	for _, n := range c.nodes {
		inv, _ := n.Inventory()
		total += len(inv)
	}
	return total
}

func (c *cluster) addrOf(n *node.Node) string {
	for _, s := range c.coord.Status().Nodes {
		if s.ID == n.ID() {
			return s.Addr
		}
	}
	c.t.Fatalf("no address for %s", n.ID())
	return ""
}

// pauseHolders takes down online nodes holding the first segment's shards
// until only `keep` online holders remain. The bridge is never paused.
func (c *cluster) pauseHolders(keep int) {
	c.t.Helper()
	var holders []*node.Node
	for _, n := range c.holders(c.coord.Status().Segments[0].ID) {
		if c.paused[n] {
			continue
		}
		if n.IsBridge() {
			holders = append([]*node.Node{n}, holders...)
		} else {
			holders = append(holders, n)
		}
	}
	for _, n := range holders[min(keep, len(holders)):] {
		c.pause(n)
	}
}

func (c *cluster) seedMirror(infohash, file string, data []byte) *client.Source {
	c.t.Helper()
	p := filepath.Join(c.mirror.Dir, infohash, file)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		c.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		c.t.Fatal(err)
	}
	return &client.Source{Infohash: infohash, File: file}
}

// --- behaviour --------------------------------------------------------------

func TestRoundTripAndDedup(t *testing.T) {
	c := newCluster(t, 12, nil)
	data := randomFile(t, 200<<10) // 4 segments, the last one short

	st, err := c.client.Add(c.ctx, bytes.NewReader(data), "/movies/a.mkv", nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Segments != 4 || st.Deduped != 0 {
		t.Fatalf("first add: %+v", st)
	}
	if !bytes.Equal(c.readBack(c.client, "/movies/a.mkv"), data) {
		t.Fatal("round trip mismatch")
	}

	// Another member adding the same bytes under their own name uploads nothing.
	bob := c.newClient("bob")
	st, err = bob.Add(c.ctx, bytes.NewReader(data), "/library/A (2001).mkv", nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Deduped != 4 || st.Uploaded != 0 {
		t.Fatalf("second add should fully dedup: %+v", st)
	}
	if !bytes.Equal(c.readBack(bob, "/library/A (2001).mkv"), data) {
		t.Fatal("deduped file mismatch")
	}

	// Without the pool secret the catalog is unreadable, even with a member key.
	outsider, _ := client.New(c.url, []byte("another pool"), "bob", c.members["bob"], c.pool, "")
	if ms, _ := outsider.List(c.ctx); len(ms) != 0 {
		t.Fatalf("foreign secret listed %d manifests", len(ms))
	}
}

func TestOrphanRepairFromPool(t *testing.T) {
	c := newCluster(t, 14, nil)
	data := randomFile(t, 50<<10) // one segment
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x", nil); err != nil {
		t.Fatal(err)
	}
	c.settle("initial orphan placement", 5*time.Second, func(s proto.SegmentStatus) bool {
		return s.Class == "orphan" && s.Durable == 9
	})

	c.pauseHolders(5) // 9 → 5 online: still readable, below the repair line

	s := c.settle("offline, not yet down", 3*time.Second, func(s proto.SegmentStatus) bool { return s.Online == 5 })
	if s.Durable != 9 {
		t.Fatalf("repaired too eagerly: %+v", s)
	}
	c.settle("repair back to 9", 10*time.Second, func(s proto.SegmentStatus) bool {
		return s.Durable == 9 && s.Online == 9 && !s.Repairing
	})
	if !bytes.Equal(c.readBack(c.client, "/x"), data) {
		t.Fatal("data changed after repair")
	}
}

func TestAnchoredLifecycle(t *testing.T) {
	c := newCluster(t, 14, nil)
	data := randomFile(t, 50<<10)
	src := c.seedMirror("deadbeef", "Show.S01E01.mkv", data)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/tv/s01e01.mkv", src); err != nil {
		t.Fatal(err)
	}

	// A bridge rebuilds it from the swarm, so the segment drops to the lean floor.
	c.settle("anchored at 6", 5*time.Second, func(s proto.SegmentStatus) bool {
		return s.Class == "anchored" && s.Durable == 6
	})

	// Lose most of the pool's shards: unreadable from the pool, but the bridge
	// rebuilds it from the swarm without waiting out the grace period.
	c.pauseHolders(2)
	c.settle("outage noticed", 3*time.Second, func(s proto.SegmentStatus) bool { return s.Online < 4 || s.Repairing })
	c.settle("swarm repair", 5*time.Second, func(s proto.SegmentStatus) bool {
		return s.Online >= 6 && !s.Repairing
	})
	if !bytes.Equal(c.readBack(c.client, "/tv/s01e01.mkv"), data) {
		t.Fatal("data mismatch after swarm repair")
	}

	// The swarm dies: demoted to orphan, the pool carries full redundancy.
	c.mirror.SetHealthy(src.Infohash, false)
	c.settle("demoted to orphan", 5*time.Second, func(s proto.SegmentStatus) bool {
		return s.Class == "orphan" && s.Target == 9
	})
	for n := range c.paused {
		c.resume(n)
	}
	c.settle("orphan at exactly 9", 10*time.Second, func(s proto.SegmentStatus) bool {
		return s.Online == 9 && s.Durable == 9 && !s.Repairing
	})
	if !bytes.Equal(c.readBack(c.client, "/tv/s01e01.mkv"), data) {
		t.Fatal("data mismatch after outage")
	}
	// Shrinks, duplicate drops and repairs all happened above; none of that
	// is misbehaviour, so no honest node may have been penalized for it.
	for _, n := range c.coord.Status().Nodes {
		if n.Strikes != 0 {
			t.Errorf("honest node %s has %d strikes", n.ID, n.Strikes)
		}
	}
}

func TestHotExpandsThenCools(t *testing.T) {
	c := newCluster(t, 16, func(cfg *coord.Config) {
		cfg.HotReadsPerShard = 30
		cfg.HeatTau = 3 * time.Second
	})
	data := randomFile(t, 50<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/hit.mkv", nil); err != nil {
		t.Fatal(err)
	}
	c.settle("cold at 9", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })

	// Reads count once per member per window, so demand has to come from
	// several members: each counted read adds 60/tau = 20 reads/min.
	readers := []*client.Client{c.client, c.newClient("bob"), c.newClient("mallory"), c.newClient("op00")}
	for _, r := range readers {
		c.readBack(r, "/hit.mkv")
		c.readBack(r, "/hit.mkv") // a repeat inside the window is ignored
	}
	s := c.settle("hot expansion", 5*time.Second, func(s proto.SegmentStatus) bool {
		return s.Durable >= 11 && !s.Repairing
	})
	t.Logf("hot: %+v", s)
	c.settle("cooled back down", 20*time.Second, func(s proto.SegmentStatus) bool {
		return s.Target == 9 && s.Durable <= 10
	})
}

func TestRemoveAndGarbageCollect(t *testing.T) {
	c := newCluster(t, 12, func(cfg *coord.Config) { cfg.GCGrace = 300 * time.Millisecond })
	data := randomFile(t, 50<<10)
	bob := c.newClient("bob")
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/a", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Add(c.ctx, bytes.NewReader(data), "/b", nil); err != nil {
		t.Fatal(err)
	}
	seg := c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 && s.Refs == 2 })

	if err := c.client.Remove(c.ctx, "/a"); err != nil {
		t.Fatal(err)
	}
	c.settle("one reference left", 3*time.Second, func(s proto.SegmentStatus) bool { return s.Refs == 1 })
	if !bytes.Equal(c.readBack(bob, "/b"), data) {
		t.Fatal("bob's copy broke when alice removed hers")
	}

	if err := bob.Remove(c.ctx, "/b"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(c.holders(seg.ID)) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("shards not collected; %d holders left", len(c.holders(seg.ID)))
		}
		c.cycle(1)
	}
	if n := len(c.coord.Status().Segments); n != 0 {
		t.Fatalf("%d live segments after GC", n)
	}
}

// A coordinator that loses its disk recovers the catalog from a node, and
// refuses writes until it has.
func TestCoordinatorRecoversCatalogFromNodes(t *testing.T) {
	c := newCluster(t, 12, nil)
	data := randomFile(t, 50<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/keep.mkv", nil); err != nil {
		t.Fatal(err)
	}
	c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })
	c.heartbeat() // nodes pull the latest entries
	head := c.coord.Catalog().Head()
	before := c.shardCount()

	cfg := c.cfg
	cfg.Fresh = false
	cfg.LogPath = filepath.Join(t.TempDir(), "lost-disk.log")
	c.startCoord(cfg)
	c.client.CoordURL = c.url
	if st := c.coord.Status(); st.WriteBlocked == "" {
		t.Fatal("empty non-fresh coordinator accepted writes")
	}
	if _, err := c.client.Add(c.ctx, bytes.NewReader(randomFile(t, 1000)), "/new", nil); err == nil {
		t.Fatal("write accepted before recovery")
	}

	c.cycle(3)
	st := c.coord.Status()
	if st.WriteBlocked != "" || st.Head != head {
		t.Fatalf("not recovered: blocked=%q head=%+v want %+v", st.WriteBlocked, st.Head, head)
	}
	if after := c.shardCount(); after != before {
		t.Fatalf("recovery changed shard count %d → %d", before, after)
	}
	c.settle("credited again via proofs", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })
	if !bytes.Equal(c.readBack(c.client, "/keep.mkv"), data) {
		t.Fatal("data unreadable after recovery")
	}
}

// --- attacks ----------------------------------------------------------------

// A coordinator with no state must not destroy shards it doesn't recognize,
// even one wrongly started as a brand-new pool.
func TestAmnesiacCoordinatorDeletesNothing(t *testing.T) {
	c := newCluster(t, 12, nil)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(randomFile(t, 50<<10)), "/x", nil); err != nil {
		t.Fatal(err)
	}
	before := c.shardCount()
	cfg := c.cfg
	cfg.Fresh, cfg.LogPath = true, ""
	c.startCoord(cfg)
	c.cycle(3)
	if after := c.shardCount(); after != before {
		t.Fatalf("empty coordinator deleted shards: %d before, %d after", before, after)
	}
}

// Hole A: unauthenticated requests and outsiders are refused.
func TestOutsidersAreRefused(t *testing.T) {
	c := newCluster(t, 12, nil)
	for _, path := range []string{"/v1/status", "/v1/log", "/v1/params"} {
		resp, err := http.Get(c.url + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("unsigned GET %s: %d", path, resp.StatusCode)
		}
	}
	stranger, _ := client.New(c.url, secret, "eve", auth.Generate(), c.pool, "")
	if _, err := stranger.Add(c.ctx, bytes.NewReader([]byte("x")), "/x", nil); err == nil {
		t.Fatal("non-member key could upload")
	}
}

// Hole B: a node claiming shards it doesn't hold gets no credit, earns
// strikes, and can't get honest copies deleted as "duplicates".
func TestLyingNodeGetsNoCredit(t *testing.T) {
	c := newCluster(t, 14, nil)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(randomFile(t, 50<<10)), "/x", nil); err != nil {
		t.Fatal(err)
	}
	s := c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })

	held := map[*node.Node]bool{}
	for _, n := range c.holders(s.ID) {
		held[n] = true
	}
	var liar *node.Node
	for _, n := range c.nodes {
		if !held[n] && !n.IsBridge() {
			liar = n
			break
		}
	}
	// The liar plants fake files for every index of the segment.
	seg, _ := c.coord.Catalog().Segment(s.ID)
	dir := filepath.Join(liar.DataDir(), "shards", s.ID[:2], s.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 12 {
		name := filepath.Join(dir, fmt.Sprintf("%d.%s", i, seg.ShardRoot))
		os.WriteFile(name, []byte("fake"), 0o644)
		os.WriteFile(name+".proof", nil, 0o644)
	}
	honest := c.shardCount() - 12

	c.cycle(5)
	st := c.coord.Status()
	for _, n := range st.Nodes {
		if n.ID == liar.ID() && n.Strikes == 0 {
			t.Fatal("lying node passed its storage proofs")
		}
	}
	if st.Segments[0].Durable != 9 {
		t.Fatalf("durable count moved: %+v", st.Segments[0])
	}
	inv, _ := liar.Inventory()
	if got := c.shardCount() - len(inv); got != honest {
		t.Fatalf("honest shards deleted: %d → %d", honest, got)
	}
}

// Hole C: uploads without a valid ticket, or with data that doesn't verify,
// are refused.
func TestShardUploadsNeedTicketAndProof(t *testing.T) {
	c := newCluster(t, 12, nil)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(randomFile(t, 50<<10)), "/x", nil); err != nil {
		t.Fatal(err)
	}
	s := c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })
	target := c.holders(s.ID)[0]
	addr := c.addrOf(target)
	seg, _ := c.coord.Catalog().Segment(s.ID)
	shardLen := codec.ShardSize(codec.Params{K: 4, MaxN: 12}, seg.CipherSize)
	junk := bytes.Repeat([]byte{0xff}, shardLen)
	ticket := func(signer ed25519.PrivateKey) *proto.Ticket {
		t := proto.Ticket{Segment: s.ID, Index: 0, NodeID: target.ID(), Root: seg.ShardRoot, CipherSize: seg.CipherSize,
			K: 4, MaxN: 12, ExpMs: time.Now().Add(time.Hour).UnixMilli()}
		t.Sign(signer)
		return &t
	}

	if err := transferPut(c.ctx, addr, s.ID, 0, junk, nil); err == nil {
		t.Fatal("upload without a ticket accepted")
	}
	if err := transferPut(c.ctx, addr, s.ID, 0, junk, ticket(c.members["mallory"])); err == nil {
		t.Fatal("upload with a forged ticket accepted")
	}
	if err := transferPut(c.ctx, addr, s.ID, 0, junk, ticket(c.coordKey)); err == nil {
		t.Fatal("junk shard accepted with a genuine ticket")
	}
}

// Hole D: one member can't overwrite or delete another member's file.
func TestMembersCantTouchOthersFiles(t *testing.T) {
	c := newCluster(t, 12, nil)
	data := randomFile(t, 50<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/alice/home.mkv", nil); err != nil {
		t.Fatal(err)
	}
	mallory := c.newClient("mallory")
	if err := mallory.Remove(c.ctx, "/alice/home.mkv"); err == nil {
		t.Fatal("mallory deleted alice's file")
	}
	if _, err := mallory.Add(c.ctx, bytes.NewReader([]byte("defaced")), "/alice/home.mkv", nil); err == nil {
		t.Fatal("mallory overwrote alice's file")
	}
	if !bytes.Equal(c.readBack(c.client, "/alice/home.mkv"), data) {
		t.Fatal("alice's file changed")
	}
}

// Hole E: attaching a torrent that's alive but doesn't contain the segment
// can't anchor it, so it keeps full redundancy.
func TestFakeTorrentCantAnchor(t *testing.T) {
	c := newCluster(t, 14, nil)
	data := randomFile(t, 50<<10)
	src := c.seedMirror("cafe", "decoy.mkv", randomFile(t, 50<<10))
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x", src); err != nil {
		t.Fatal(err)
	}
	c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })
	c.cycle(15)
	s := c.coord.Status().Segments[0]
	if s.Class == "anchored" || s.Target != 9 {
		t.Fatalf("fake torrent anchored the segment: %+v", s)
	}
}

// Dedup squatting: junk registered under a real segment ID would poison
// every later honest upload of that file. The coordinator verifies first.
func TestDedupSquattingRejected(t *testing.T) {
	c := newCluster(t, 12, nil)
	data := randomFile(t, 50<<10)
	_, ct, id, _ := codec.SealSegment(secret, data)
	shards, _ := codec.Encode(codec.Params{K: 4, MaxN: 12}, randomFile(t, len(ct)))
	tree := codec.NewTree(shards)
	root := codec.HashToHex(tree.Root)

	mallory := auth.NewIdentity(c.members["mallory"])
	var prep proto.PrepareResponse
	if err := postJSON(c.ctx, mallory, c.url+"/v1/prepare", proto.PrepareRequest{Segment: id, CipherSize: len(ct), Root: root}, &prep); err != nil {
		t.Fatal(err)
	}
	var placed []proto.Location
	for _, tg := range prep.Targets {
		if err := transferPutProof(c.ctx, tg.Addr, id, tg.Index, shards[tg.Index], tree.Proof(tg.Index), &tg.Ticket); err == nil {
			placed = append(placed, tg.Location)
		}
	}
	if len(placed) < 4 {
		t.Fatalf("setup: only %d junk shards placed", len(placed))
	}
	if err := postJSON(c.ctx, mallory, c.url+"/v1/commit", proto.CommitRequest{Segment: id, Root: root, Placed: placed}, nil); err == nil {
		t.Fatal("coordinator committed junk under a real segment id")
	}

	st, err := c.client.Add(c.ctx, bytes.NewReader(data), "/real.mkv", nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Deduped != 0 {
		t.Fatal("honest upload deduped onto squatted junk")
	}
	if !bytes.Equal(c.readBack(c.client, "/real.mkv"), data) {
		t.Fatal("honest data unreadable")
	}
	// The junk shards sit under a root the catalog never committed, so the
	// nodes are told to drop them.
	c.cycle(3)
	for _, n := range c.nodes {
		inv, _ := n.Inventory()
		for _, k := range inv {
			if k.Segment == id && k.Root == root {
				t.Fatalf("junk shard still on %s", n.ID())
			}
		}
	}
}

// One member running many nodes still gets at most one shard per segment.
func TestSybilNodesShareOneFailureDomain(t *testing.T) {
	c := newCluster(t, 16, nil)
	for i := range 8 {
		c.coordPool.Nodes[i].Owner = "mallory" // the coordinator's view of ownership
	}
	c.heartbeat() // the coordinator reads ownership from the pool file on heartbeat
	if _, err := c.client.Add(c.ctx, bytes.NewReader(randomFile(t, 50<<10)), "/x", nil); err != nil {
		t.Fatal(err)
	}
	c.cycle(3)
	s := c.coord.Status().Segments[0]
	owned := 0
	for _, n := range c.holders(s.ID) {
		if e, _ := c.pool.Node(n.ID()); e.Owner == "mallory" {
			owned++
		}
	}
	if owned > 1 {
		t.Fatalf("one owner holds %d shards of a segment", owned)
	}
}

// Reliability-aware placement: a segment's redundancy follows how much its
// holders can be trusted. Proven owners let it run lean; when holders start
// failing proofs, the pool adds redundancy on its own.
func TestRedundancyFollowsReliability(t *testing.T) {
	c := newCluster(t, 20, func(cfg *coord.Config) {
		cfg.TargetLoss, cfg.AnchoredTargetLoss = 1e-6, 1e-3
		cfg.MinN, cfg.ShrinkMargin = 6, 10
		cfg.Reliability = reliability.DefaultParams()
		cfg.Reliability.OfflineAfter = cfg.OfflineAfter
		cfg.Reliability.PriorWeight = 2 * time.Second // new owners earn trust in seconds here
		cfg.Reliability.PriorProofs = 2
		cfg.Reliability.HalfLife = time.Hour
	})
	data := randomFile(t, 50<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x", nil); err != nil {
		t.Fatal(err)
	}
	// New owners start pessimistic, so the segment starts wide.
	first := c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable >= 9 && !s.Repairing })
	t.Logf("new owners: %d shards, loss %.1e", first.Durable, first.LossProb)

	// As owners prove themselves the estimate falls and the pool shrinks it.
	lean := c.settle("shrunk on proven owners", 20*time.Second, func(s proto.SegmentStatus) bool {
		return s.Durable < first.Durable && s.LossProb <= 1e-6 && !s.Repairing
	})
	t.Logf("proven owners: %d shards, loss %.1e", lean.Durable, lean.LossProb)

	// Holders go bad: their shard files silently rot, so proofs start failing.
	for _, n := range c.holders(lean.ID)[:lean.Durable/2] {
		filepath.WalkDir(filepath.Join(n.DataDir(), "shards"), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && filepath.Ext(p) != ".proof" {
				os.WriteFile(p, bytes.Repeat([]byte{0}, 64), 0o644)
			}
			return nil
		})
	}
	healed := c.settle("redundancy restored on good owners", 20*time.Second, func(s proto.SegmentStatus) bool {
		return s.LossProb <= 1e-6 && s.Online >= 6 && !s.Repairing
	})
	t.Logf("after rot: %d shards, loss %.1e", healed.Durable, healed.LossProb)
	if !bytes.Equal(c.readBack(c.client, "/x"), data) {
		t.Fatal("data unreadable after holders rotted")
	}
}

// --- operator controls --------------------------------------------------

func (c *cluster) node(id string) *node.Node {
	for _, n := range c.nodes {
		if n.ID() == id {
			return n
		}
	}
	c.t.Fatalf("no node %s", id)
	return nil
}

func (c *cluster) usedBy(n *node.Node) int64 { return n.Capacity().Used }

// A node with a small quota never stores more than it offered, and the
// coordinator stops placing on it once it's full.
func TestQuotaIsRespected(t *testing.T) {
	c := newCluster(t, 14, nil)
	small := c.node("n00")
	shard := int64(codec.ShardSize(codec.Params{K: 4, MaxN: 12}, 64<<10+16))
	small.SetLimits(2*shard, 0, 0, false) // room for two shards
	c.heartbeat()

	for i := range 6 {
		if _, err := c.client.Add(c.ctx, bytes.NewReader(randomFile(t, 64<<10)), fmt.Sprintf("/f%d", i), nil); err != nil {
			t.Fatal(err)
		}
		c.heartbeat()
	}
	c.cycle(3)
	if used := c.usedBy(small); used > 2*shard {
		t.Fatalf("node stored %d bytes past its %d quota", used, 2*shard)
	}
	for _, s := range c.coord.Status().Segments {
		if s.Durable < 9 {
			t.Fatalf("segment under-placed because of one small node: %+v", s)
		}
	}
}

// Draining moves every shard off a node before deleting it, so durability
// never dips, and the node ends up empty.
func TestDrainEmptiesNodeWithoutLosingDurability(t *testing.T) {
	c := newCluster(t, 14, nil)
	data := randomFile(t, 128<<10) // 2 segments
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x", nil); err != nil {
		t.Fatal(err)
	}
	c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })

	var leaving *node.Node
	for _, n := range c.nodes {
		if inv, _ := n.Inventory(); len(inv) > 0 && !n.IsBridge() {
			leaving = n
			break
		}
	}
	leaving.SetLimits(0, 0, 0, true)
	deadline := time.Now().Add(15 * time.Second)
	for {
		c.heartbeat()
		c.coord.Tick()
		for _, s := range c.coord.Status().Segments {
			if s.Durable < 9 {
				t.Fatalf("durability dipped during drain: %+v", s)
			}
		}
		if inv, _ := leaving.Inventory(); len(inv) == 0 {
			break
		}
		if time.Now().After(deadline) {
			inv, _ := leaving.Inventory()
			t.Fatalf("drain incomplete: %d shards left", len(inv))
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !bytes.Equal(c.readBack(c.client, "/x"), data) {
		t.Fatal("data unreadable after drain")
	}
	if used := leaving.Capacity().Used; used != 0 {
		t.Fatalf("drained node still accounts %d bytes used", used)
	}
}

// The upload cap throttles shard serving.
func TestUploadCapThrottles(t *testing.T) {
	c := newCluster(t, 12, func(cfg *coord.Config) { cfg.SegmentSize = 8 << 20 })
	data := randomFile(t, 8<<20) // one segment, 2 MiB shards
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/big", nil); err != nil {
		t.Fatal(err)
	}
	c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })
	for _, n := range c.nodes {
		n.SetLimits(0, 2<<20, 0, false) // 2 MiB/s each
	}
	c.heartbeat() // keep nodes online for the coordinator under -race slowdowns

	// 4 shards of 2 MiB from 4 nodes in parallel at 2 MiB/s each, less the
	// 0.5 MiB burst allowance: at least ~0.75 s. Uncapped it's milliseconds.
	start := time.Now()
	if !bytes.Equal(c.readBack(c.client, "/big"), data) {
		t.Fatal("mismatch")
	}
	if d := time.Since(start); d < 650*time.Millisecond {
		t.Fatalf("capped read finished in %v; throttle not applied", d)
	}
}

// Lazy repair that falls short (here: holders expire one tick apart, so the
// first repair is sized for a partial loss) must still end at the floor, not
// park just above the trigger line.
func TestPartialRepairIsToppedUp(t *testing.T) {
	c := newCluster(t, 14, nil)
	data := randomFile(t, 50<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x", nil); err != nil {
		t.Fatal(err)
	}
	c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })
	c.pauseHolders(7) // first wave: 2 holders gone, 7 left (below 9-1)
	c.settle("first repair done", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Online >= 8 && !s.Repairing })
	c.pauseHolders(7) // second wave from the repaired set
	c.settle("back at the floor", 10*time.Second, func(s proto.SegmentStatus) bool {
		return s.Durable == 9 && s.Online == 9 && !s.Repairing
	})
}

// --- reachability -------------------------------------------------------

func noSTUN() []string { return []string{"127.0.0.1:9"} } // fails fast, never leaves the machine

// Nodes whose direct address can't be reached fall back to the relay, and
// the pool keeps working through them; a reachable node is confirmed
// direct by the coordinator's dial-back.
func TestUnreachableNodesUseRelay(t *testing.T) {
	c := newCluster(t, 12, nil)
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	var relayed []*node.Node
	for i, n := range c.nodes {
		addr, _ := n.Addr()
		// 9 of 12 relayed: each segment's 9 shards then keep at least 6 (> k)
		// on relayed nodes, so the reads below must go through the relay.
		if i < 9 && !n.IsBridge() {
			c.direct[n].blocked.Store(true) // behind CGNAT: nothing gets in
			relayed = append(relayed, n)
		}
		go n.RunReachability(ctx, node.ReachOptions{Mode: "auto", Announce: addr, STUN: noSTUN(), RelayURL: c.url})
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ok := true
		for _, n := range c.nodes {
			r := n.Reach()
			want := "direct"
			if slices.Contains(relayed, n) {
				want = "relay"
			}
			if r.Reach != want || (want == "relay" && !r.RelayUp) {
				ok = false
			}
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			for _, n := range c.nodes {
				t.Logf("%s: %+v", n.ID(), n.Reach())
			}
			t.Fatal("nodes didn't settle on direct/relay")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := len(c.relay.Connected()); got != len(relayed) {
		t.Fatalf("%d nodes tunnelled, want %d", got, len(relayed))
	}
	t.Logf("relay suggestion for a CGNAT node: %q", relayed[0].Reach().Suggestion)

	c.heartbeat() // advertise the new addresses
	data := randomFile(t, 200<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x", nil); err != nil {
		t.Fatal(err)
	}
	c.cycle(3) // storage proofs reach relayed nodes through the tunnel too
	viaRelay := 0
	for _, n := range relayed {
		if inv, _ := n.Inventory(); len(inv) > 0 {
			viaRelay++
		}
	}
	if viaRelay == 0 {
		t.Fatal("no shards landed on relayed nodes; the test proves nothing")
	}
	// Force reads through relayed nodes: take the direct ones offline.
	for _, n := range c.nodes {
		if !slices.Contains(relayed, n) {
			c.pause(n)
		}
	}
	got := c.readBack(c.client, "/x")
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch through relay")
	}
	for _, s := range c.coord.Status().Nodes {
		if s.Strikes != 0 {
			t.Errorf("node %s got strikes over the relay", s.ID)
		}
	}
}
