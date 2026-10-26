// Package coord is the pool coordinator. Durable facts (segments, files,
// swarm anchoring, tombstones) live in the signed catalog log, which every
// node replicates. Soft state (where shards are, who is online, how hot a
// segment is) lives here in memory and is rebuilt from heartbeats.
//
// The coordinator schedules placement, repair, hot expansion, cold shrinking,
// garbage collection and bridge checks. It never sees plaintext or content
// keys, and it trusts no node's word: a shard only counts once the
// coordinator placed and verified it, or the node proved it holds it.
package coord

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/catalog"
	"mediapool/internal/codec"
	"mediapool/internal/invite"
	"mediapool/internal/proto"
	"mediapool/internal/reliability"
	"mediapool/internal/transfer"
)

type Config struct {
	Params codec.Params

	// Durability floors. Anchored segments have a verified healthy external
	// swarm to fall back on and run lean; orphans carry full redundancy.
	AnchoredN int
	OrphanN   int

	// Reliability-aware durability. With TargetLoss set, a segment's shard
	// count is driven by the estimated chance of losing it, computed from
	// each holder's observed reliability, instead of the fixed floors:
	// shards on proven owners go further, shards on new or flaky owners
	// need company. Anchored segments use the looser AnchoredTargetLoss,
	// since the public swarm backs them. MinN bounds how lean it may get.
	// ShrinkMargin is hysteresis: shards are dropped only while the loss
	// estimate stays below TargetLoss/ShrinkMargin.
	TargetLoss         float64
	AnchoredTargetLoss float64
	MinN               int
	ShrinkMargin       float64
	Reliability        reliability.Params
	ScoresPath         string

	// Lazy repair: rebuild only once durable shards drop this far below the
	// floor. Hot expansion is not lazy.
	RepairSlack int
	// Delete surplus shards only when the count exceeds the target by more
	// than this, so a segment hovering at a heat threshold doesn't flap.
	ShrinkSlack int

	// HotReadsPerShard is the read rate (reads/min, at most one per member
	// per HeatTau/30) that earns one extra shard above the floor. HotBudget
	// caps extra shards across the pool, so faked demand can't consume
	// unbounded capacity.
	HotReadsPerShard float64
	HeatTau          time.Duration
	HotBudget        int

	// A node that misses heartbeats for OfflineAfter can't serve reads. Its
	// shards still count as durable until DownAfter, so ordinary reboots and
	// outages don't trigger repair traffic.
	OfflineAfter time.Duration
	DownAfter    time.Duration

	// Storage proofs: ProofsPerTick random challenges per tick. A shard a
	// node reports that the coordinator didn't verify is credited only after
	// it passes one. At MaxStrikes failed proofs a node gets no new shards.
	ProofsPerTick int
	MaxStrikes    int

	// GCGrace is how long a segment must sit unreferenced before it's
	// collected, so an upload in progress isn't raced.
	GCGrace time.Duration

	TaskTimeout     time.Duration
	TicketTTL       time.Duration
	SwarmCheckEvery time.Duration
	TickEvery       time.Duration

	Key     ed25519.PrivateKey
	Pool    *auth.Pool
	LogPath string
	// Fresh declares that this coordinator starts a new pool. Without it, a
	// coordinator with an empty catalog refuses writes until it has caught
	// up from a node, so lost state can't silently fork the pool.
	Fresh bool

	HTTP *http.Client
	Logf func(format string, args ...any)
}

func DefaultConfig() Config {
	return Config{
		Params:             codec.Params{K: 10, MaxN: 40},
		AnchoredN:          14,
		OrphanN:            30,
		TargetLoss:         1e-9,
		AnchoredTargetLoss: 1e-5,
		MinN:               12,
		ShrinkMargin:       100,
		Reliability:        reliability.DefaultParams(),
		RepairSlack:        3,
		ShrinkSlack:        1,
		HotReadsPerShard:   2,
		HeatTau:            30 * time.Minute,
		HotBudget:          10000,
		OfflineAfter:       2 * time.Minute,
		DownAfter:          48 * time.Hour,
		ProofsPerTick:      4,
		MaxStrikes:         3,
		GCGrace:            24 * time.Hour,
		TaskTimeout:        10 * time.Minute,
		TicketTTL:          30 * time.Minute,
		SwarmCheckEvery:    6 * time.Hour,
		TickEvery:          10 * time.Second,
	}
}

func (c Config) Validate() error {
	if err := c.Params.Validate(); err != nil {
		return err
	}
	if c.AnchoredN < c.Params.K || c.OrphanN < c.AnchoredN || c.OrphanN > c.Params.MaxN {
		return fmt.Errorf("coord: need k <= anchored_n <= orphan_n <= max_n, got %d/%d/%d/%d",
			c.Params.K, c.AnchoredN, c.OrphanN, c.Params.MaxN)
	}
	if c.TargetLoss > 0 && (c.MinN < c.Params.K || c.MinN > c.Params.MaxN || c.ShrinkMargin < 1) {
		return fmt.Errorf("coord: need k <= min_n <= max_n and shrink_margin >= 1")
	}
	if c.Key == nil || c.Pool == nil {
		return errors.New("coord: key and pool are required")
	}
	if pk, err := c.Pool.CoordinatorKey(); err != nil || !pk.Equal(c.Key.Public()) {
		return errors.New("coord: key doesn't match the pool file's coordinator key")
	}
	return nil
}

type shardState int

const (
	unverified shardState = iota // reported by the node: doesn't count until proven
	placed                       // placed by a task: counts, and is proven first
	credited
)

type node struct {
	entry    auth.NodeEntry
	addr     string
	cap      proto.Capacity
	reach    string
	pledged  int64 // bytes of tickets issued this heartbeat, not yet reflected in cap.Free
	lastSeen time.Time
	head     catalog.Head
	shards   map[proto.ShardKey]shardState
	deleting map[proto.ShardKey]bool // asked to delete; ignored in inventory until gone
	strikes  int
	tasks    []proto.Task
	deletes  []proto.ShardKey
	checks   []proto.HealthCheck
}

// segInfo is soft per-segment state. Everything durable is in the catalog.
type segInfo struct {
	heat         float64 // smoothed reads per second
	heatAt       time.Time
	readers      map[string]time.Time // member → last counted read
	swarmChecked time.Time
	pending      *pending
	// refilling is set once lazy repair triggers and cleared when the
	// segment is back at its floor, so a repair that fell short (some
	// holders expired a tick later, a push failed) finishes the job instead
	// of parking just above the trigger line.
	refilling bool
}

type pending struct {
	taskID   string
	nodeID   string
	deadline time.Time
}

// upload is a segment between prepare and commit. It enters the catalog only
// after the coordinator verified the uploaded shards rebuild it.
type upload struct {
	add     catalog.SegmentAdd
	targets []proto.PutTarget
	expires time.Time
}

type Coordinator struct {
	cfg    Config
	cat    *catalog.Catalog
	id     *auth.Identity
	verify auth.Verifier

	mu          sync.Mutex
	nodes       map[string]*node
	segs        map[string]*segInfo
	uploads     map[string]*upload
	taskSeq     int
	bridgeRR    int
	ready       bool
	blocked     string                        // why writes are refused, if they are
	scores      map[string]*reliability.Score // by owner
	scoresSaved time.Time
}

func New(cfg Config) (*Coordinator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: time.Minute}
	}
	cat, err := catalog.Open(cfg.LogPath, cfg.Key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	cfg.Pool.Attach(cat)
	c := &Coordinator{
		cfg: cfg, cat: cat, id: auth.NewIdentity(cfg.Key),
		nodes: map[string]*node{}, segs: map[string]*segInfo{}, uploads: map[string]*upload{},
		scores: map[string]*reliability.Score{},
	}
	if cfg.Reliability.OfflineAfter == 0 {
		c.cfg.Reliability = reliability.DefaultParams()
		c.cfg.Reliability.OfflineAfter = cfg.OfflineAfter
	}
	if err := c.loadScores(); err != nil {
		return nil, err
	}
	marker := cfg.LogPath + ".created"
	if cfg.Fresh && cfg.LogPath != "" && cat.Head().Seq == 0 {
		if _, err := os.Stat(marker); err == nil {
			// This coordinator created a pool here before and its catalog
			// is now empty: the log was lost. Starting fresh would fork the
			// pool, so recover from the nodes instead.
			cfg.Logf("coordinator: catalog %s is empty but a pool was created here before; ignoring -fresh and recovering from nodes", cfg.LogPath)
			cfg.Fresh = false
		} else if err := os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	if cat.Head().Seq > 0 || cfg.Fresh {
		c.ready = true
		if err := c.ensureFounders(); err != nil {
			return nil, err
		}
	} else {
		c.blocked = "catalog is empty and this isn't a fresh pool: waiting to recover it from a node"
		cfg.Logf("coordinator: %s", c.blocked)
	}
	return c, nil
}

func (c *Coordinator) Catalog() *catalog.Catalog { return c.cat }
func (c *Coordinator) Close() error              { return c.cat.Close() }

// Run ticks the scheduler until stop is closed.
func (c *Coordinator) Run(stop <-chan struct{}) {
	t := time.NewTicker(c.cfg.TickEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.Tick()
		}
	}
}

func (c *Coordinator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/heartbeat", c.nodeOnly(c.handleHeartbeat))
	mux.HandleFunc("POST /v1/task-result", c.nodeOnly(c.handleTaskResult))
	mux.HandleFunc("POST /v1/swarm-report", c.nodeOnly(c.handleSwarmReport))
	mux.HandleFunc("POST /v1/probe", c.nodeOnly(c.handleProbe))
	mux.HandleFunc("POST /v1/prepare", c.memberOnly(c.handlePrepare))
	mux.HandleFunc("POST /v1/commit", c.memberOnly(c.handleCommit))
	mux.HandleFunc("POST /v1/files", c.memberOnly(c.handleFilePut))
	mux.HandleFunc("POST /v1/files/delete", c.memberOnly(c.handleFileDel))
	mux.HandleFunc("GET /v1/locate/{seg}", c.memberOnly(c.handleLocate))
	mux.HandleFunc("POST /v1/invites", c.memberOnly(c.handleInviteCreate))
	mux.HandleFunc("POST /v1/join", c.handleJoin) // unauthenticated: the invite code is the credential
	mux.HandleFunc("POST /v1/nodes", c.memberOnly(c.handleNodeAdd))
	mux.HandleFunc("POST /v1/nodes/remove", c.memberOnly(c.handleNodeRemove))
	mux.HandleFunc("POST /v1/nodes/bridge", c.memberOnly(c.handleNodeBridge))
	mux.HandleFunc("POST /v1/members/remove", c.memberOnly(c.handleMemberRemove))
	mux.HandleFunc("GET /v1/members", c.anyone(func(w http.ResponseWriter, _ *http.Request, _ auth.Principal, _ []byte) {
		writeJSON(w, map[string]any{"members": c.cfg.Pool.AllMembers(), "nodes": c.cfg.Pool.AllNodes()})
	}))
	mux.HandleFunc("GET /v1/log", c.anyone(func(w http.ResponseWriter, r *http.Request, _ auth.Principal, _ []byte) {
		c.cat.ServeLog(w, r)
	}))
	mux.HandleFunc("GET /v1/params", c.anyone(func(w http.ResponseWriter, _ *http.Request, _ auth.Principal, _ []byte) {
		writeJSON(w, c.cfg.Params)
	}))
	mux.HandleFunc("GET /v1/status", c.anyone(func(w http.ResponseWriter, _ *http.Request, _ auth.Principal, _ []byte) {
		writeJSON(w, c.Status())
	}))
	return mux
}

// --- authentication -------------------------------------------------------

type authedHandler func(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte)

func (c *Coordinator) anyone(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pub, err := c.verify.Verify(r, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		p, ok := c.cfg.Pool.Lookup(pub)
		if !ok {
			http.Error(w, "key is not in the pool", http.StatusForbidden)
			return
		}
		h(w, r, p, body)
	}
}

func (c *Coordinator) nodeOnly(h authedHandler) http.HandlerFunc {
	return c.anyone(func(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte) {
		if p.Node == nil {
			http.Error(w, "node key required", http.StatusForbidden)
			return
		}
		h(w, r, p, body)
	})
}

func (c *Coordinator) memberOnly(h authedHandler) http.HandlerFunc {
	return c.anyone(func(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte) {
		if p.Member == "" {
			http.Error(w, "member key required", http.StatusForbidden)
			return
		}
		h(w, r, p, body)
	})
}

// writable reports whether the catalog may be written. Caller holds c.mu.
func (c *Coordinator) writable(w http.ResponseWriter) bool {
	if !c.ready {
		http.Error(w, c.blocked, http.StatusServiceUnavailable)
		return false
	}
	return true
}

// --- policy ---------------------------------------------------------------

func anchored(s catalog.Segment) bool { return s.Source != nil && s.Swarm == catalog.SwarmHealthy }

func class(s catalog.Segment) string {
	switch {
	case anchored(s):
		return "anchored"
	case s.Source != nil && s.Swarm == catalog.SwarmUnknown:
		return "unverified"
	default:
		return "orphan"
	}
}

func (c *Coordinator) info(id string) *segInfo {
	si := c.segs[id]
	if si == nil {
		si = &segInfo{readers: map[string]time.Time{}}
		c.segs[id] = si
	}
	return si
}

// heat returns the smoothed read rate in reads/second as of now.
func (c *Coordinator) heat(si *segInfo, now time.Time) float64 {
	if si.heatAt.IsZero() {
		return 0
	}
	return si.heat * math.Exp(-now.Sub(si.heatAt).Seconds()/c.cfg.HeatTau.Seconds())
}

// recordRead counts at most one read per member per HeatTau/30, so one
// member hammering a segment can't make it look popular.
func (c *Coordinator) recordRead(si *segInfo, member string, now time.Time) {
	if last, ok := si.readers[member]; ok && now.Sub(last) < c.cfg.HeatTau/30 {
		return
	}
	si.readers[member] = now
	for m, t := range si.readers {
		if now.Sub(t) > c.cfg.HeatTau {
			delete(si.readers, m)
		}
	}
	si.heat = c.heat(si, now) + 1/c.cfg.HeatTau.Seconds()
	si.heatAt = now
}

func (c *Coordinator) base(s catalog.Segment) int {
	if anchored(s) {
		return c.cfg.AnchoredN
	}
	return c.cfg.OrphanN // unverified sources get full redundancy until a bridge vouches
}

func (c *Coordinator) extra(s catalog.Segment, now time.Time) int {
	return int(c.heat(c.info(s.ID), now) * 60 / c.cfg.HotReadsPerShard)
}

func (c *Coordinator) online(n *node, now time.Time) bool {
	return now.Sub(n.lastSeen) < c.cfg.OfflineAfter
}
func (c *Coordinator) alive(n *node, now time.Time) bool {
	return now.Sub(n.lastSeen) < c.cfg.DownAfter
}
func (c *Coordinator) trusted(n *node) bool { return n.strikes < c.cfg.MaxStrikes }

// holders indexes every credited shard of alive nodes: segment → index →
// node IDs. Inventory only ever holds shards at the committed root.
func (c *Coordinator) holders(now time.Time) map[string]map[int][]string {
	h := map[string]map[int][]string{}
	for id, n := range c.nodes {
		if !c.alive(n, now) {
			continue
		}
		for k, st := range n.shards {
			if st == unverified {
				continue
			}
			if h[k.Segment] == nil {
				h[k.Segment] = map[int][]string{}
			}
			h[k.Segment][k.Index] = append(h[k.Segment][k.Index], id)
		}
	}
	for _, byIdx := range h {
		for _, ids := range byIdx {
			slices.Sort(ids)
		}
	}
	return h
}

// pickNodes chooses up to n online, trusted nodes, at most one per owner and
// none from an owner already holding a shard of the segment. An owner's
// nodes are one failure domain, so running many nodes buys no extra share of
// any segment. preferBridge puts high-bandwidth bridges first, which is where
// hot shards belong.
func (c *Coordinator) pickNodes(n int, excludeOwners map[string]bool, preferBridge bool, size int64, now time.Time) []*node {
	var cands []*node
	for _, nd := range c.nodes {
		if !excludeOwners[nd.entry.Owner] && c.online(nd, now) && c.trusted(nd) && c.hasRoom(nd, size) {
			cands = append(cands, nd)
		}
	}
	// With reliability on, prefer proven owners (bucketed, so similar
	// owners still share load evenly). New owners sort last: they get
	// shards when the proven ones are exhausted or already hold one, and
	// earn trust from uptime and proofs in the meantime.
	bucket := func(n *node) int {
		if c.cfg.TargetLoss == 0 {
			return 0
		}
		return int(c.failProb(n) * 50)
	}
	slices.SortFunc(cands, func(a, b *node) int {
		if preferBridge {
			// Hot shards go where the upload is: bridges first, then the
			// operators who offered the most bandwidth (0 = uncapped).
			if a.entry.Bridge != b.entry.Bridge {
				if a.entry.Bridge {
					return -1
				}
				return 1
			}
			if d := cmp.Compare(upRank(b), upRank(a)); d != 0 {
				return d
			}
		}
		// Otherwise fill by fraction of offered space used, so a big disk
		// takes proportionally more shards than a small one.
		return cmp.Or(cmp.Compare(bucket(a), bucket(b)), cmp.Compare(fill(a), fill(b)), cmp.Compare(a.entry.ID, b.entry.ID))
	})
	var out []*node
	owners := map[string]bool{}
	for _, nd := range cands {
		if len(out) == n {
			break
		}
		if !owners[nd.entry.Owner] {
			owners[nd.entry.Owner] = true
			out = append(out, nd)
		}
	}
	return out
}

// hasRoom reports whether n will accept a shard of this size: not draining,
// and enough reported free space after the tickets already issued to it.
func (c *Coordinator) hasRoom(n *node, size int64) bool {
	if n.cap.Drain {
		return false
	}
	return n.cap.Free < 0 || n.cap.Free-n.pledged >= size
}

// fill is the fraction of a node's offered space in use; unknown capacity
// ranks by shard count instead.
func fill(n *node) float64 {
	total := n.cap.Used + n.cap.Free
	if n.cap.Free < 0 || total <= 0 {
		return float64(len(n.shards))
	}
	return float64(n.cap.Used+n.pledged) / float64(total)
}

func upRank(n *node) int64 {
	if n.reach == "relay" {
		return 1 // every byte crosses the relay: last choice for hot data
	}
	if n.cap.UploadBps == 0 {
		return math.MaxInt64
	}
	return n.cap.UploadBps
}

func (c *Coordinator) onlineBridge(now time.Time) *node {
	var bridges []*node
	for _, n := range c.nodes {
		if n.entry.Bridge && c.online(n, now) && c.trusted(n) {
			bridges = append(bridges, n)
		}
	}
	if len(bridges) == 0 {
		return nil
	}
	slices.SortFunc(bridges, func(a, b *node) int { return cmp.Compare(a.entry.ID, b.entry.ID) })
	c.bridgeRR++
	return bridges[c.bridgeRR%len(bridges)]
}

func (c *Coordinator) score(owner string) *reliability.Score {
	s := c.scores[owner]
	if s == nil {
		s = &reliability.Score{}
		c.scores[owner] = s
	}
	return s
}

func (c *Coordinator) failProb(n *node) float64 {
	return c.cfg.Reliability.FailProb(*c.score(n.entry.Owner))
}

func (c *Coordinator) targetLoss(s catalog.Segment) float64 {
	if anchored(s) {
		return c.cfg.AnchoredTargetLoss
	}
	return c.cfg.TargetLoss
}

// lossOf estimates the chance a segment held by these nodes (one per owner)
// becomes unrecoverable.
func (c *Coordinator) lossOf(holders []*node) float64 {
	q := make([]float64, len(holders))
	for i, n := range holders {
		q[i] = c.failProb(n)
	}
	return reliability.LossProb(q, c.cfg.Params.K)
}

func (c *Coordinator) shardSize(s catalog.Segment) int64 {
	return int64(codec.ShardSize(c.cfg.Params, s.CipherSize))
}

func location(n *node, idx int) proto.Location {
	return proto.Location{Index: idx, NodeID: n.entry.ID, Addr: n.addr}
}

func (c *Coordinator) ticket(n *node, seg string, idx int, root string, size int, now time.Time) proto.PutTarget {
	t := proto.Ticket{
		Segment: seg, Index: idx, NodeID: n.entry.ID, Root: root, CipherSize: size,
		K: c.cfg.Params.K, MaxN: c.cfg.Params.MaxN, ExpMs: now.Add(c.cfg.TicketTTL).UnixMilli(),
	}
	t.Sign(c.cfg.Key)
	n.pledged += int64(codec.ShardSize(c.cfg.Params, size))
	return proto.PutTarget{Location: location(n, idx), Ticket: t}
}

func (c *Coordinator) appendEntry(typ string, body any) (catalog.Entry, error) {
	return c.cat.Append(c.cfg.Key, typ, body)
}

// --- scheduler ------------------------------------------------------------

// Tick runs one scheduling pass: recovery, storage proofs, then every segment.
func (c *Coordinator) Tick() {
	c.mu.Lock()
	if !c.ready {
		c.recoverLocked()
	}
	now := time.Now()
	challenges := c.pickChallenges(now)
	if c.ready {
		h := c.holders(now)
		budget := c.cfg.HotBudget
		for _, s := range c.cat.LiveSegments() {
			c.schedule(s, h[s.ID], now, &budget)
		}
		c.collectGarbage(now)
		c.saveScores(now)
		for id, u := range c.uploads {
			if now.After(u.expires) {
				delete(c.uploads, id)
			}
		}
	}
	c.mu.Unlock()

	// Proofs talk to nodes over the network; run them without the lock.
	for _, ch := range challenges {
		c.challenge(ch)
	}
}

func (c *Coordinator) schedule(s catalog.Segment, byIdx map[int][]string, now time.Time, hotBudget *int) {
	si := c.info(s.ID)
	if si.pending != nil && now.After(si.pending.deadline) {
		c.cfg.Logf("segment %.12s: task %s timed out", s.ID, si.pending.taskID)
		si.pending = nil
	}
	c.scheduleSwarmCheck(s, si, now)
	if si.pending != nil {
		return
	}
	if c.evacuate(s, si, byIdx, now) {
		return
	}

	alive := map[int]bool{}
	var online []proto.Location
	owners := map[string]bool{}
	for idx, ids := range byIdx {
		alive[idx] = true
		seen := false
		for _, id := range ids {
			n := c.nodes[id]
			owners[n.entry.Owner] = true
			if !seen && c.online(n, now) {
				online = append(online, location(n, idx))
				seen = true
			}
		}
	}

	if c.cfg.TargetLoss > 0 {
		c.scheduleByLoss(s, si, byIdx, alive, online, owners, now, hotBudget)
		return
	}

	base, k := c.base(s), c.cfg.Params.K
	extra := min(c.extra(s, now), max(*hotBudget, 0), c.cfg.Params.MaxN-base)
	*hotBudget -= extra
	target := base + extra
	bridgeCanRebuild := s.Source != nil && s.Swarm != catalog.SwarmDead && c.onlineBridge(now) != nil

	switch {
	case len(online) < k && bridgeCanRebuild:
		// Unreadable right now, but a bridge can rebuild it from the swarm
		// without touching pool bandwidth: don't wait out the grace period.
		// Surplus left when the absent holders return is shrunk away later.
		have := map[int]bool{}
		for _, l := range online {
			have[l.Index] = true
		}
		c.repair(s, si, have, online, owners, target-len(online), extra > 0, now)
	case len(alive) < base-c.cfg.RepairSlack,
		si.refilling && len(alive) < base,
		extra > 0 && len(alive) < target:
		si.refilling = true
		c.repair(s, si, alive, online, owners, target-len(alive), extra > 0, now)
	case len(alive) > target+c.cfg.ShrinkSlack:
		c.shrink(s, byIdx, len(alive)-target)
	}
	if len(alive) >= base {
		si.refilling = false
	}
	c.dropDuplicates(s, byIdx, now)
}

// scheduleByLoss sizes a segment by its estimated loss probability. Repair
// adds holders until the estimate is under target; shrinking drops the least
// reliable holders while it stays well under. Heat adds capacity on top, as
// in the fixed-floor mode.
func (c *Coordinator) scheduleByLoss(s catalog.Segment, si *segInfo, byIdx map[int][]string, alive map[int]bool, online []proto.Location, owners map[string]bool, now time.Time, hotBudget *int) {
	k, maxN := c.cfg.Params.K, c.cfg.Params.MaxN
	holderOf := map[int]*node{}
	var holders []*node
	for idx, ids := range byIdx {
		n := c.nodes[ids[0]]
		for _, id := range ids[1:] { // with duplicates, rate the better copy
			if c.failProb(c.nodes[id]) < c.failProb(n) {
				n = c.nodes[id]
			}
		}
		holderOf[idx] = n
		holders = append(holders, n)
	}
	target := c.targetLoss(s)
	extra := min(c.extra(s, now), max(*hotBudget, 0))
	*hotBudget -= extra
	bridgeCanRebuild := s.Source != nil && s.Swarm != catalog.SwarmDead && c.onlineBridge(now) != nil

	// How many more holders would bring the estimate under target, picking
	// the candidates placement would actually choose.
	need := func(base []*node, excl map[string]bool) int {
		cands := c.pickNodes(maxN, excl, false, c.shardSize(s), now)
		cur := slices.Clone(base)
		added := 0
		for (len(cur) < c.cfg.MinN || c.lossOf(cur) > target) && added < len(cands) && len(cur) < maxN {
			cur = append(cur, cands[added])
			added++
		}
		return added
	}

	switch {
	case len(online) < k && bridgeCanRebuild:
		have := map[int]bool{}
		var onl []*node
		for _, l := range online {
			have[l.Index] = true
			onl = append(onl, c.nodes[l.NodeID])
		}
		if n := need(onl, owners) + extra; n > 0 {
			c.repair(s, si, have, online, owners, n, extra > 0, now)
		}
	case len(holders) < c.cfg.MinN || c.lossOf(holders) > target:
		if n := need(holders, owners); n > 0 {
			c.repair(s, si, alive, online, owners, n+extra, extra > 0, now)
		}
	case extra > 0 && len(holders) < min(maxN, c.cfg.MinN+extra):
		c.repair(s, si, alive, online, owners, min(maxN, c.cfg.MinN+extra)-len(holders), true, now)
	case extra == 0 && len(holders) > c.cfg.MinN:
		// Drop the least reliable holders while safely under target. Shard
		// indices go with their holders here, not highest-index-first.
		idxs := make([]int, 0, len(holderOf))
		for idx := range holderOf {
			idxs = append(idxs, idx)
		}
		slices.SortFunc(idxs, func(a, b int) int {
			return cmp.Or(cmp.Compare(c.failProb(holderOf[b]), c.failProb(holderOf[a])), cmp.Compare(b, a))
		})
		keep := slices.Clone(holders)
		var drop []int
		for _, idx := range idxs {
			if len(keep) <= c.cfg.MinN {
				break
			}
			rest := slices.DeleteFunc(slices.Clone(keep), func(n *node) bool { return n == holderOf[idx] })
			if c.lossOf(rest) > target/c.cfg.ShrinkMargin {
				break
			}
			keep, drop = rest, append(drop, idx)
		}
		for _, idx := range drop {
			for _, id := range byIdx[idx] {
				c.deleteShard(c.nodes[id], proto.ShardKey{Segment: s.ID, Index: idx, Root: s.ShardRoot})
			}
			delete(byIdx, idx)
		}
		if len(drop) > 0 {
			c.cfg.Logf("segment %.12s [%s]: shrank by %d shards (loss %.1e)", s.ID, class(s), len(drop), c.lossOf(keep))
		}
	}
	c.dropDuplicates(s, byIdx, now)
}

// evacuate moves one shard off a node that is draining or over its quota.
// The shard is copied to a new holder first; the old copy is deleted only
// once the new one is credited, so evacuation never lowers durability. It
// returns true if it scheduled work for this segment.
func (c *Coordinator) evacuate(s catalog.Segment, si *segInfo, byIdx map[int][]string, now time.Time) bool {
	for idx, ids := range byIdx {
		var leaving, staying []string
		for _, id := range ids {
			n := c.nodes[id]
			if n.cap.Drain || (n.cap.Quota > 0 && n.cap.Used > n.cap.Quota) {
				leaving = append(leaving, id)
			} else {
				staying = append(staying, id)
			}
		}
		if len(leaving) == 0 {
			continue
		}
		if len(staying) > 0 {
			// Already copied: let go of the leaving copies.
			for _, id := range leaving {
				c.deleteShard(c.nodes[id], proto.ShardKey{Segment: s.ID, Index: idx, Root: s.ShardRoot})
			}
			return true
		}
		src := c.nodes[leaving[0]]
		if !c.online(src, now) {
			continue
		}
		owners := map[string]bool{}
		for _, ids := range byIdx {
			for _, id := range ids {
				if !slices.Contains(leaving, id) {
					owners[c.nodes[id].entry.Owner] = true
				}
			}
		}
		dst := c.pickNodes(1, owners, false, c.shardSize(s), now)
		if len(dst) == 0 {
			continue // nowhere to go yet; keep it where it is
		}
		// A move is a single shard copy: the destination fetches it from the
		// leaving node and stores it under a ticket, no decoding needed.
		c.taskSeq++
		task := proto.Task{
			ID: "t" + strconv.Itoa(c.taskSeq), Segment: s.ID, CipherSize: s.CipherSize, Params: c.cfg.Params, Root: s.ShardRoot,
			Move: &proto.Location{Index: idx, NodeID: src.entry.ID, Addr: src.addr},
			Put:  []proto.PutTarget{c.ticket(dst[0], s.ID, idx, s.ShardRoot, s.CipherSize, now)},
		}
		dst[0].tasks = append(dst[0].tasks, task)
		si.pending = &pending{taskID: task.ID, nodeID: dst[0].entry.ID, deadline: now.Add(c.cfg.TaskTimeout)}
		c.cfg.Logf("segment %.12s: moving shard %d off %s to %s (%s)", s.ID, idx, src.entry.ID, dst[0].entry.ID, task.ID)
		return true
	}
	return false
}

// scheduleSwarmCheck asks a bridge about a segment's torrent. A segment that
// isn't anchored needs a verify check (rebuild from the swarm and match);
// once anchored, liveness checks keep it there.
func (c *Coordinator) scheduleSwarmCheck(s catalog.Segment, si *segInfo, now time.Time) {
	if s.Source == nil || s.Swarm == catalog.SwarmDead || now.Sub(si.swarmChecked) < c.cfg.SwarmCheckEvery {
		return
	}
	if b := c.onlineBridge(now); b != nil {
		b.checks = append(b.checks, proto.HealthCheck{Segment: s.ID, SourceBlob: s.Source, Verify: !anchored(s)})
		si.swarmChecked = now
	}
}

// repair rebuilds `need` shard indices absent from `have`.
func (c *Coordinator) repair(s catalog.Segment, si *segInfo, have map[int]bool, online []proto.Location, owners map[string]bool, need int, hot bool, now time.Time) {
	var missing []int
	for i := 0; i < c.cfg.Params.MaxN && len(missing) < need; i++ {
		if !have[i] {
			missing = append(missing, i)
		}
	}
	targets := c.pickNodes(len(missing), owners, hot, c.shardSize(s), now)
	if len(targets) == 0 {
		return
	}
	task := proto.Task{Segment: s.ID, CipherSize: s.CipherSize, Params: c.cfg.Params, Root: s.ShardRoot}
	for i, n := range targets {
		task.Put = append(task.Put, c.ticket(n, s.ID, missing[i], s.ShardRoot, s.CipherSize, now))
	}

	var exec *node
	bridge := c.onlineBridge(now)
	switch {
	case anchored(s) && bridge != nil:
		// Repair traffic is what kills home-node storage; for anchored segments
		// it comes from the public swarm instead of pool uplinks.
		exec, task.SourceBlob = bridge, s.Source
	case len(online) >= c.cfg.Params.K:
		exec, task.Fetch = targets[0], online
	case s.Source != nil && s.Swarm != catalog.SwarmDead && bridge != nil:
		exec, task.SourceBlob = bridge, s.Source
	default:
		c.cfg.Logf("segment %.12s: %d shards online, need %d and no bridge source; waiting", s.ID, len(online), c.cfg.Params.K)
		return
	}

	c.taskSeq++
	task.ID = "t" + strconv.Itoa(c.taskSeq)
	exec.tasks = append(exec.tasks, task)
	si.pending = &pending{taskID: task.ID, nodeID: exec.entry.ID, deadline: now.Add(c.cfg.TaskTimeout)}
	how := "pool"
	if task.SourceBlob != nil {
		how = "swarm"
	}
	c.cfg.Logf("segment %.12s [%s]: rebuilding %d shards from %s on %s (%s)",
		s.ID, class(s), len(task.Put), how, exec.entry.ID, task.ID)
}

// shrink deletes the n highest-indexed shards. Low indices are the data
// shards, so keeping them lets a full set be read without decoding.
func (c *Coordinator) shrink(s catalog.Segment, byIdx map[int][]string, n int) {
	idxs := make([]int, 0, len(byIdx))
	for i := range byIdx {
		idxs = append(idxs, i)
	}
	slices.Sort(idxs)
	slices.Reverse(idxs)
	for _, idx := range idxs[:n] {
		for _, id := range byIdx[idx] {
			c.deleteShard(c.nodes[id], proto.ShardKey{Segment: s.ID, Index: idx, Root: s.ShardRoot})
		}
		delete(byIdx, idx)
	}
	c.cfg.Logf("segment %.12s [%s]: shrank by %d shards", s.ID, class(s), n)
}

// dropDuplicates removes extra copies of a shard index, which appear when an
// absent node's shards were rebuilt elsewhere and it returns. It only acts
// once every copy is online, and keeps the copy on the node with the fewest
// failed proofs, so it never trades a good copy for a doubtful one.
func (c *Coordinator) dropDuplicates(s catalog.Segment, byIdx map[int][]string, now time.Time) {
	for idx, ids := range byIdx {
		if len(ids) < 2 || slices.ContainsFunc(ids, func(id string) bool { return !c.online(c.nodes[id], now) }) {
			continue
		}
		keep := slices.MinFunc(ids, func(a, b string) int {
			return cmp.Or(cmp.Compare(c.nodes[a].strikes, c.nodes[b].strikes), cmp.Compare(a, b))
		})
		for _, id := range ids {
			if id != keep {
				c.deleteShard(c.nodes[id], proto.ShardKey{Segment: s.ID, Index: idx, Root: s.ShardRoot})
			}
		}
	}
}

func (c *Coordinator) deleteShard(n *node, k proto.ShardKey) {
	delete(n.shards, k)
	n.deleting[k] = true
	n.deletes = append(n.deletes, k)
}

// hold records a shard the coordinator placed, cancelling any pending delete.
func (n *node) hold(k proto.ShardKey, st shardState) {
	delete(n.deleting, k)
	if cur, ok := n.shards[k]; !ok || cur < st {
		n.shards[k] = st
	}
}

// collectGarbage tombstones segments nobody has referenced for GCGrace.
// Nodes delete their shards once the tombstone reaches their own replica.
func (c *Coordinator) collectGarbage(now time.Time) {
	for _, s := range c.cat.LiveSegments() {
		if s.Refs > 0 || now.Sub(time.UnixMilli(s.RefsChangedMs)) < c.cfg.GCGrace {
			continue
		}
		if _, err := c.appendEntry(catalog.TypeSegmentGC, catalog.SegmentGC{ID: s.ID}); err != nil {
			c.cfg.Logf("gc %.12s: %v", s.ID, err)
			continue
		}
		delete(c.segs, s.ID)
		for _, n := range c.nodes {
			for k := range n.shards {
				if k.Segment == s.ID {
					c.deleteShard(n, k)
				}
			}
		}
		c.cfg.Logf("segment %.12s: collected (unreferenced)", s.ID)
	}
}

// --- recovery -------------------------------------------------------------

// recoverLocked catches an empty catalog up from the nodes: sync from the
// node with the longest log, then check every node's head is a prefix of the
// result. If two nodes hold different histories the pool has forked, and
// the coordinator stays read-only for a human to resolve. Caller holds c.mu;
// it's released during the network sync.
func (c *Coordinator) recoverLocked() {
	now := time.Now()
	var best *node
	for _, n := range c.nodes {
		if c.online(n, now) && (best == nil || n.head.Seq > best.head.Seq) {
			best = n
		}
	}
	if best == nil || best.head.Seq == 0 {
		return
	}
	addr, id := best.addr, best.entry.ID
	c.mu.Unlock()
	got, err := c.cat.Sync(context.Background(), c.cfg.HTTP, addr, c.id.Signer())
	c.mu.Lock()
	if err != nil {
		c.cfg.Logf("recovery from %s: %v", id, err)
		return
	}
	for _, n := range c.nodes {
		if n.head.Seq > 0 && c.cat.HashAt(n.head.Seq) != n.head.Hash {
			c.blocked = fmt.Sprintf("pool catalog has forked: node %s disagrees at entry %d", n.entry.ID, n.head.Seq)
			c.cfg.Logf("coordinator: %s", c.blocked)
			return
		}
	}
	c.ready, c.blocked = true, ""
	if err := c.ensureFounders(); err != nil {
		c.cfg.Logf("coordinator: recording founders: %v", err)
	}
	c.cfg.Logf("coordinator: recovered %d catalog entries from %s, head %d", got, id, c.cat.Head().Seq)
}

// --- storage proofs -------------------------------------------------------

type challenge struct {
	nodeID string
	addr   string
	key    proto.ShardKey
	chunk  int
	size   int
	nonce  string
}

// pickChallenges chooses random shards to prove. Unverified shards go first:
// proving them is the only way they're ever credited.
func (c *Coordinator) pickChallenges(now time.Time) []challenge {
	var unv, cred []challenge
	for _, n := range c.nodes {
		if !c.online(n, now) {
			continue
		}
		for k, st := range n.shards {
			s, ok := c.cat.Segment(k.Segment)
			if !ok || !s.Live() || s.ShardRoot != k.Root {
				continue
			}
			size := codec.ShardSize(c.cfg.Params, s.CipherSize)
			ch := challenge{nodeID: n.entry.ID, addr: n.addr, key: k, chunk: mrand.IntN(codec.NumChunks(size)), size: size}
			if st == credited {
				cred = append(cred, ch)
			} else {
				unv = append(unv, ch)
			}
		}
	}
	mrand.Shuffle(len(unv), func(i, j int) { unv[i], unv[j] = unv[j], unv[i] })
	mrand.Shuffle(len(cred), func(i, j int) { cred[i], cred[j] = cred[j], cred[i] })
	out := append(unv, cred...)
	out = out[:min(len(out), c.cfg.ProofsPerTick)]
	for i := range out {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		out[i].nonce = hex.EncodeToString(b)
	}
	return out
}

func (c *Coordinator) challenge(ch challenge) {
	ok, reason := c.prove(ch)
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.nodes[ch.nodeID]
	if n == nil {
		return
	}
	if ok {
		c.cfg.Reliability.Proof(c.score(n.entry.Owner), true, time.Now())
		if _, held := n.shards[ch.key]; held {
			n.shards[ch.key] = credited
		}
		return
	}
	if reason == "" {
		return // unreachable: heartbeats and grace periods handle that
	}
	c.cfg.Reliability.Proof(c.score(n.entry.Owner), false, time.Now())
	delete(n.shards, ch.key)
	n.strikes++
	c.cfg.Logf("node %s failed storage proof for %.12s/%d: %s (strike %d)", ch.nodeID, ch.key.Segment, ch.key.Index, reason, n.strikes)
}

// prove runs one challenge. A reachable node that can't produce a valid,
// signed proof gets a reason; a network failure gets none.
func (c *Coordinator) prove(ch challenge) (bool, string) {
	q := url.Values{"root": {ch.key.Root}, "chunk": {strconv.Itoa(ch.chunk)}, "nonce": {ch.nonce}}
	u := fmt.Sprintf("%s/v1/proof/%s/%d?%s", ch.addr, ch.key.Segment, ch.key.Index, q.Encode())
	var resp proto.ProofResponse
	err := transfer.GetJSON(context.Background(), c.cfg.HTTP, c.id, u, &resp)
	var he *transfer.HTTPError
	switch {
	case errors.As(err, &he) && he.Status == http.StatusServiceUnavailable:
		return false, ""
	case errors.As(err, &he):
		return false, he.Msg
	case err != nil:
		return false, ""
	}
	entry, ok := c.cfg.Pool.Node(ch.nodeID)
	pub, _ := hex.DecodeString(entry.Key)
	root, _ := codec.HexToHash(ch.key.Root)
	shardHash, err1 := codec.HexToHash(resp.ShardHash)
	segProof, err2 := codec.DecodeProof(resp.SegProof)
	chunkProof, err3 := codec.DecodeProof(resp.ChunkProof)
	switch {
	case !ok || err1 != nil || err2 != nil || err3 != nil:
		return false, "malformed proof"
	case !ed25519.Verify(pub, proto.ProofSigMessage(ch.nonce, ch.key.Segment, ch.key.Index, ch.key.Root, ch.chunk, resp.Chunk), resp.Sig):
		return false, "proof not signed by the node"
	case !codec.VerifyShardHash(root, c.cfg.Params.MaxN, ch.key.Index, shardHash, segProof):
		return false, "shard isn't part of the segment"
	case !codec.VerifyChunk(shardHash, ch.size, ch.chunk, resp.Chunk, chunkProof):
		return false, "chunk doesn't match the shard"
	}
	return true, ""
}

// --- node handlers --------------------------------------------------------

func (c *Coordinator) handleHeartbeat(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var req proto.HeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Node.Addr == "" {
		http.Error(w, "bad heartbeat", http.StatusBadRequest)
		return
	}
	if req.Node.ID != p.Node.ID {
		http.Error(w, "heartbeat for another node", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	now := time.Now()
	n := c.nodes[p.Node.ID]
	if n == nil {
		n = &node{shards: map[proto.ShardKey]shardState{}, deleting: map[proto.ShardKey]bool{}}
		c.nodes[p.Node.ID] = n
		c.cfg.Logf("node %s joined (owner %s, %s, bridge=%v)", p.Node.ID, p.Node.Owner, req.Node.Addr, p.Node.Bridge)
	}
	c.cfg.Reliability.Heartbeat(c.score(p.Node.Owner), n.lastSeen, now)
	n.entry, n.addr, n.lastSeen, n.head = *p.Node, req.Node.Addr, now, req.Head
	n.cap, n.pledged, n.reach = req.Node.Capacity, 0, req.Node.Reach

	// Reconcile the inventory. Shards no longer reported are gone. New ones
	// start unverified and count only after a storage proof, so a node can't
	// claim shards it doesn't have. Shards of segments we don't know are left
	// alone: our catalog may be the one that's behind.
	reported := make(map[proto.ShardKey]bool, len(req.Inventory))
	for _, k := range req.Inventory {
		reported[k] = true
		if _, held := n.shards[k]; held || n.deleting[k] {
			continue // an inventory taken before a pending delete ran can't revive it
		}
		s, known := c.cat.Segment(k.Segment)
		switch {
		case !known:
		case s.Live() && s.ShardRoot == k.Root:
			n.shards[k] = unverified
		default:
			n.deletes = append(n.deletes, k) // collected segment, or junk under a real ID
		}
	}
	for k := range n.shards {
		if !reported[k] {
			delete(n.shards, k)
		}
	}
	for k := range n.deleting {
		if !reported[k] {
			delete(n.deleting, k) // the node complied
		}
	}

	resp := proto.HeartbeatResponse{Head: c.cat.Head(), Ready: c.ready, Deletes: n.deletes}
	if c.ready {
		resp.Tasks, resp.HealthChecks = n.tasks, n.checks
		n.tasks, n.checks = nil, nil
	}
	n.deletes = nil
	c.mu.Unlock()

	out, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(proto.CoordSigHeader, base64.StdEncoding.EncodeToString(ed25519.Sign(c.cfg.Key, proto.HeartbeatSigMessage(p.Node.ID, out))))
	_, _ = w.Write(out)
}

// handleTaskResult records shards a task placed. Only the node the task was
// sent to can report it.
func (c *Coordinator) handleTaskResult(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var res proto.TaskResult
	if err := json.Unmarshal(body, &res); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, si := range c.segs {
		if si.pending == nil || si.pending.taskID != res.TaskID {
			continue
		}
		if si.pending.nodeID != p.Node.ID {
			http.Error(w, "task belongs to another node", http.StatusForbidden)
			return
		}
		si.pending = nil
		if res.Error != "" {
			c.cfg.Logf("segment %.12s: task %s failed on %s: %s", id, res.TaskID, p.Node.ID, res.Error)
		}
		// The receiving node verified each shard against the root before
		// storing it. Count them now so repair doesn't run again, and prove
		// them first in case the executor lied about placing them.
		s, _ := c.cat.Segment(id)
		for _, l := range res.Placed {
			if n := c.nodes[l.NodeID]; n != nil {
				n.hold(proto.ShardKey{Segment: id, Index: l.Index, Root: s.ShardRoot}, placed)
			}
		}
		break
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleSwarmReport(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var rep proto.SwarmReport
	if err := json.Unmarshal(body, &rep); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !p.Node.Bridge {
		http.Error(w, "only bridge nodes report on swarms", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.writable(w) {
		return
	}
	s, ok := c.cat.Segment(rep.Segment)
	if !ok || !s.Live() || s.Source == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Anchoring needs proof the swarm serves these exact bytes; a liveness
	// check can only keep an anchored segment anchored, or demote it.
	healthy := rep.Healthy && (rep.Verified || anchored(s))
	if rep.Healthy && !healthy {
		w.WriteHeader(http.StatusNoContent) // alive but unverified: no change
		return
	}
	state := catalog.SwarmDead
	if healthy {
		state = catalog.SwarmHealthy
	}
	if state != s.Swarm {
		if _, err := c.appendEntry(catalog.TypeSegmentSwarm, catalog.SegmentSwarm{ID: s.ID, Healthy: healthy}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c.cfg.Logf("segment %.12s: swarm %s (reported by %s)", s.ID, state, p.Node.ID)
	}
	c.info(s.ID).swarmChecked = time.Now()
	w.WriteHeader(http.StatusNoContent)
}

// handleProbe dials a node's candidate addresses back and reports which
// ones reach it. Each candidate must answer a fresh nonce with a signature
// from the node's own key, so an address that leads to some other machine
// doesn't count.
func (c *Coordinator) handleProbe(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte) {
	var req proto.ProbeRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Candidates) > 8 {
		http.Error(w, "bad probe request", http.StatusBadRequest)
		return
	}
	pub, _ := hex.DecodeString(p.Node.Key)
	hc := &http.Client{Timeout: 4 * time.Second}
	resp := proto.ProbeResponse{Reachable: []string{}, Errors: map[string]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, cand := range req.Candidates {
		u, err := url.Parse(cand)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			resp.Errors[cand] = "not an http(s) URL"
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			nonce := hex.EncodeToString(b)
			var pr proto.PingResponse
			err := transfer.GetJSON(r.Context(), hc, nil, strings.TrimRight(cand, "/")+"/v1/ping?nonce="+nonce, &pr)
			if err == nil && (pr.ID != p.Node.ID || !ed25519.Verify(pub, proto.PingSigMessage(p.Node.ID, nonce), pr.Sig)) {
				err = errors.New("answered, but not by this node")
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				resp.Errors[cand] = err.Error()
			} else {
				resp.Reachable = append(resp.Reachable, cand)
			}
		}()
	}
	wg.Wait()
	slices.SortFunc(resp.Reachable, func(a, b string) int {
		return cmp.Compare(slices.Index(req.Candidates, a), slices.Index(req.Candidates, b))
	})
	writeJSON(w, resp)
}

// --- member handlers ------------------------------------------------------

func (c *Coordinator) handlePrepare(w http.ResponseWriter, _ *http.Request, _ auth.Principal, body []byte) {
	var req proto.PrepareRequest
	if err := json.Unmarshal(body, &req); err != nil || req.CipherSize <= 0 || len(req.Segment) != 64 {
		http.Error(w, "bad prepare request", http.StatusBadRequest)
		return
	}
	if _, err := codec.HexToHash(req.Root); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.writable(w) {
		return
	}
	now := time.Now()

	if s, ok := c.cat.Segment(req.Segment); ok && s.Live() {
		// Someone already stored these bytes. Attach the torrent source if the
		// pool lacks a working one; a bridge verifies it before it anchors.
		if req.SourceBlob != nil && (s.Source == nil || s.Swarm == catalog.SwarmDead) {
			if _, err := c.appendEntry(catalog.TypeSegmentSource, catalog.SegmentSource{ID: s.ID, Source: req.SourceBlob}); err == nil {
				c.info(s.ID).swarmChecked = time.Time{}
			}
		}
		writeJSON(w, proto.PrepareResponse{Exists: true})
		return
	}

	targets := c.pickNodes(c.cfg.OrphanN, nil, false, int64(codec.ShardSize(c.cfg.Params, req.CipherSize)), now)
	if len(targets) < c.cfg.Params.K {
		http.Error(w, fmt.Sprintf("only %d failure domains online, need at least k=%d", len(targets), c.cfg.Params.K), http.StatusServiceUnavailable)
		return
	}
	u := &upload{
		add:     catalog.SegmentAdd{ID: req.Segment, CipherSize: req.CipherSize, ShardRoot: req.Root, Source: req.SourceBlob},
		expires: now.Add(c.cfg.TicketTTL),
	}
	for i, n := range targets {
		u.targets = append(u.targets, c.ticket(n, req.Segment, i, req.Root, req.CipherSize, now))
	}
	// Keyed by segment and root, so concurrent uploads of one ID with
	// different roots can't commit each other's shards.
	c.uploads[req.Segment+"/"+req.Root] = u
	writeJSON(w, proto.PrepareResponse{Targets: u.targets})
}

// handleCommit admits a segment to the catalog only after the coordinator
// fetched k uploaded shards, rebuilt the ciphertext, checked it hashes to the
// segment ID and re-encodes to the claimed root. Without this a member could
// register junk under the ID of a popular file, and every honest member
// adding that file later would dedup onto the junk.
func (c *Coordinator) handleCommit(w http.ResponseWriter, r *http.Request, _ auth.Principal, body []byte) {
	var req proto.CommitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := req.Segment + "/" + req.Root
	c.mu.Lock()
	if !c.writable(w) {
		c.mu.Unlock()
		return
	}
	u := c.uploads[key]
	if u == nil {
		c.mu.Unlock()
		http.Error(w, "no pending upload for this segment and root", http.StatusNotFound)
		return
	}
	issued := map[int]proto.Location{}
	for _, t := range u.targets {
		issued[t.Index] = t.Location
	}
	var placed []proto.Location
	for _, l := range req.Placed {
		if t, ok := issued[l.Index]; ok && t.NodeID == l.NodeID {
			placed = append(placed, t) // only locations we issued tickets for
		}
	}
	add := u.add
	c.mu.Unlock()

	if err := c.verifyUpload(r.Context(), add, placed); err != nil {
		http.Error(w, "upload rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.uploads, key)
	if s, ok := c.cat.Segment(add.ID); ok && s.Live() {
		w.WriteHeader(http.StatusNoContent) // a concurrent identical upload won
		return
	}
	if _, err := c.appendEntry(catalog.TypeSegmentAdd, add); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, l := range placed {
		if n := c.nodes[l.NodeID]; n != nil {
			n.hold(proto.ShardKey{Segment: add.ID, Index: l.Index, Root: add.ShardRoot}, credited)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) verifyUpload(ctx context.Context, add catalog.SegmentAdd, placed []proto.Location) error {
	root, err := codec.HexToHash(add.ShardRoot)
	if err != nil {
		return err
	}
	shards, err := transfer.FetchAny(ctx, c.cfg.HTTP, c.id, add.ID, placed, root, c.cfg.Params.K, c.cfg.Params.MaxN)
	if err != nil {
		return err
	}
	ct, err := codec.Join(c.cfg.Params, shards, add.CipherSize)
	if err != nil {
		return err
	}
	if codec.HashHex(ct) != add.ID {
		return errors.New("shards don't rebuild the segment id")
	}
	full, err := codec.Encode(c.cfg.Params, ct)
	if err != nil {
		return err
	}
	if codec.NewTree(full).Root != root {
		return errors.New("segment doesn't re-encode to the claimed root")
	}
	return nil
}

func (c *Coordinator) handleFilePut(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var b catalog.FilePut
	if err := json.Unmarshal(body, &b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.writeFile(w, p, b.Author, catalog.TypeFilePut, b)
}

func (c *Coordinator) handleFileDel(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var b catalog.FileDel
	if err := json.Unmarshal(body, &b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.writeFile(w, p, b.Author, catalog.TypeFileDel, b)
}

// writeFile logs a member-signed file change. The catalog checks the
// author's signature and ownership; this checks the sender is the author.
func (c *Coordinator) writeFile(w http.ResponseWriter, p auth.Principal, author, typ string, body any) {
	if author != p.Member {
		http.Error(w, "members can only write their own files", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.writable(w) {
		return
	}
	e, err := c.appendEntry(typ, body)
	if errors.Is(err, catalog.ErrInvalid) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, catalog.Head{Seq: e.Seq, Hash: e.Hash()})
}

func (c *Coordinator) handleLocate(w http.ResponseWriter, r *http.Request, p auth.Principal, _ []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.cat.Segment(r.PathValue("seg"))
	if !ok || !s.Live() {
		http.Error(w, "unknown segment", http.StatusNotFound)
		return
	}
	now := time.Now()
	c.recordRead(c.info(s.ID), p.Member, now)
	resp := proto.LocateResponse{Segment: s.ID, Root: s.ShardRoot, CipherSize: s.CipherSize, Params: c.cfg.Params}
	for _, n := range c.nodes {
		if !c.online(n, now) {
			continue
		}
		for k := range n.shards {
			if k.Segment == s.ID {
				resp.Shards = append(resp.Shards, location(n, k.Index))
			}
		}
	}
	// Spread load across holders; clients fetch the first k that verify.
	mrand.Shuffle(len(resp.Shards), func(i, j int) { resp.Shards[i], resp.Shards[j] = resp.Shards[j], resp.Shards[i] })
	writeJSON(w, resp)
}

func (c *Coordinator) Status() proto.StatusResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	h := c.holders(now)
	out := proto.StatusResponse{Params: c.cfg.Params, Head: c.cat.Head(), WriteBlocked: c.blocked}
	for _, n := range c.nodes {
		out.Nodes = append(out.Nodes, proto.NodeStatus{
			ID: n.entry.ID, Owner: n.entry.Owner, Addr: n.addr, Bridge: n.entry.Bridge,
			Online: c.online(n, now), Shards: len(n.shards), Strikes: n.strikes, LastSeen: n.lastSeen,
			FailProb: c.failProb(n), Capacity: n.cap, Reach: n.reach,
		})
	}
	for _, s := range c.cat.LiveSegments() {
		si := c.info(s.ID)
		st := proto.SegmentStatus{
			ID: s.ID, Class: class(s), Refs: s.Refs, Size: s.CipherSize,
			Target:  min(c.base(s)+c.extra(s, now), c.cfg.Params.MaxN),
			Durable: len(h[s.ID]), HeatPerMin: c.heat(si, now) * 60, Repairing: si.pending != nil,
		}
		var holders []*node
		for _, ids := range h[s.ID] {
			holders = append(holders, c.nodes[ids[0]])
			if slices.ContainsFunc(ids, func(id string) bool { return c.online(c.nodes[id], now) }) {
				st.Online++
			}
		}
		st.LossProb = c.lossOf(holders)
		if c.cfg.TargetLoss > 0 {
			st.Target = 0 // no fixed target: sized by loss
		}
		out.Segments = append(out.Segments, st)
	}
	slices.SortFunc(out.Nodes, func(a, b proto.NodeStatus) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- reliability persistence ----------------------------------------------

// Scores are soft state, but losing them would reset every owner to the new-
// owner prior and trigger a pool-wide repair storm, so they're saved.
func (c *Coordinator) loadScores() error {
	if c.cfg.ScoresPath == "" {
		return nil
	}
	b, err := os.ReadFile(c.cfg.ScoresPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c.scores)
}

func (c *Coordinator) saveScores(now time.Time) {
	if c.cfg.ScoresPath == "" || now.Sub(c.scoresSaved) < time.Minute {
		return
	}
	b, err := json.Marshal(c.scores)
	if err == nil {
		tmp := c.cfg.ScoresPath + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, c.cfg.ScoresPath)
		}
	}
	if err != nil {
		c.cfg.Logf("save scores: %v", err)
		return
	}
	c.scoresSaved = now
}

// --- membership -------------------------------------------------------------

// ensureFounders records pool.json's members and nodes in the catalog if
// they aren't there yet. On a new pool these become the first entries, so
// every replica knows the founders before any of their files.
func (c *Coordinator) ensureFounders() error {
	have := map[string]bool{}
	for _, m := range c.cat.JoinedMembers() {
		have["m/"+m.Name] = true
	}
	for _, n := range c.cat.JoinedNodes() {
		have["n/"+n.ID] = true
	}
	for _, m := range c.cfg.Pool.Members {
		if !have["m/"+m.Name] {
			if _, err := c.appendEntry(catalog.TypeMemberAdd, catalog.MemberAdd{Name: m.Name, Key: m.Key, Admin: m.Admin}); err != nil {
				return fmt.Errorf("founder %s: %w", m.Name, err)
			}
		}
	}
	for _, n := range c.cfg.Pool.Nodes {
		if have["n/"+n.ID] {
			continue
		}
		if _, err := c.appendEntry(catalog.TypeNodeAdd, catalog.NodeAdd{ID: n.ID, Key: n.Key, Owner: n.Owner}); err != nil {
			return fmt.Errorf("founder node %s: %w", n.ID, err)
		}
		if n.Bridge {
			if _, err := c.appendEntry(catalog.TypeNodeBridge, catalog.NodeBridge{ID: n.ID, Bridge: true}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Coordinator) isAdmin(name string) bool {
	m, ok := c.cfg.Pool.Member(name)
	return ok && m.Admin
}

// appendMembership logs a membership entry, mapping catalog rule
// violations to 409 so callers see why.
func (c *Coordinator) appendMembership(w http.ResponseWriter, typ string, body any) bool {
	if !c.writable(w) {
		return false
	}
	if _, err := c.appendEntry(typ, body); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, catalog.ErrInvalid) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return false
	}
	return true
}

func (c *Coordinator) handleInviteCreate(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var b catalog.InviteCreate
	if err := json.Unmarshal(body, &b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !c.isAdmin(p.Member) {
		http.Error(w, "only admins can invite", http.StatusForbidden)
		return
	}
	b.By = p.Member
	if b.ExpiresMs == 0 {
		b.ExpiresMs = time.Now().Add(7 * 24 * time.Hour).UnixMilli()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appendMembership(w, catalog.TypeInviteCreate, b) {
		c.cfg.Logf("invite created by %s (for %q, admin=%v)", p.Member, b.Name, b.Admin)
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleJoin redeems an invite. The joiner proves it holds the keys it
// registers by signing the request with each of them.
func (c *Coordinator) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req invite.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "bad join request", http.StatusBadRequest)
		return
	}
	check := func(keyHex string, sig []byte) bool {
		k, err := hex.DecodeString(keyHex)
		return err == nil && len(k) == ed25519.PublicKeySize && ed25519.Verify(k, req.Message(), sig)
	}
	if !check(req.MemberKey, req.MemberSig) || (req.NodeKey != "" && !check(req.NodeKey, req.NodeSig)) {
		http.Error(w, "join request not signed by the keys it registers", http.StatusBadRequest)
		return
	}
	hash := invite.Hash(req.Code)
	c.mu.Lock()
	defer c.mu.Unlock()
	inv, err := c.cat.InviteStatus(hash, time.Now().UnixMilli())
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	// Check the node first so a bad node id doesn't consume the invite.
	if req.NodeID != "" {
		if _, taken := c.cfg.Pool.Node(req.NodeID); taken {
			http.Error(w, fmt.Sprintf("node id %q is taken", req.NodeID), http.StatusConflict)
			return
		}
		if req.NodeKey == req.MemberKey {
			http.Error(w, "node and member need different keys", http.StatusBadRequest)
			return
		}
	}
	if !c.appendMembership(w, catalog.TypeMemberAdd, catalog.MemberAdd{Name: req.Member, Key: req.MemberKey, Admin: inv.Admin, Invite: hash}) {
		return
	}
	if req.NodeID != "" && !c.appendMembership(w, catalog.TypeNodeAdd, catalog.NodeAdd{ID: req.NodeID, Key: req.NodeKey, Owner: req.Member}) {
		return
	}
	c.cfg.Logf("%s joined (invited by %s), node %q", req.Member, inv.By, req.NodeID)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleNodeAdd(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var req invite.NodeAddRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	k, err := hex.DecodeString(req.Key)
	if err != nil || len(k) != ed25519.PublicKeySize || !ed25519.Verify(k, invite.NodeAddMessage(req.ID, p.Member, req.Key), req.Sig) {
		http.Error(w, "node add not signed by the node key", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appendMembership(w, catalog.TypeNodeAdd, catalog.NodeAdd{ID: req.ID, Key: req.Key, Owner: p.Member}) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *Coordinator) handleNodeRemove(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var b catalog.NodeRemove
	if err := json.Unmarshal(body, &b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n, ok := c.cfg.Pool.Node(b.ID)
	if !ok || (n.Owner != p.Member && !c.isAdmin(p.Member)) {
		http.Error(w, "only the node's owner or an admin can remove it", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appendMembership(w, catalog.TypeNodeRemove, b) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *Coordinator) handleNodeBridge(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var b catalog.NodeBridge
	if err := json.Unmarshal(body, &b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !c.isAdmin(p.Member) {
		http.Error(w, "only admins grant the bridge role", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appendMembership(w, catalog.TypeNodeBridge, b) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *Coordinator) handleMemberRemove(w http.ResponseWriter, _ *http.Request, p auth.Principal, body []byte) {
	var b catalog.MemberRemove
	if err := json.Unmarshal(body, &b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !c.isAdmin(p.Member) {
		http.Error(w, "only admins remove members", http.StatusForbidden)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appendMembership(w, catalog.TypeMemberRemove, b) {
		c.cfg.Logf("member %s removed by %s", b.Name, p.Member)
		w.WriteHeader(http.StatusNoContent)
	}
}
