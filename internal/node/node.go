// Package node is the storage daemon each pool member runs. It stores shards
// on disk, serves them to pool members, keeps a verified replica of the
// catalog, heartbeats its inventory to the coordinator, answers storage
// proofs and executes rebuild tasks.
//
// A node trusts the coordinator for scheduling but not for destruction: it
// stores only shards that verify against a coordinator-signed ticket, and
// deletes shards only when its own catalog replica says the segment is gone
// or the shard is a stale duplicate, within a per-heartbeat budget. A plain
// storage node never needs the pool secret; a bridge node does, so it can
// open torrent source references and re-encrypt segments rebuilt from the
// public swarm.
package node

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/bridge"
	"mediapool/internal/catalog"
	"mediapool/internal/codec"
	"mediapool/internal/diskfree"
	"mediapool/internal/limits"
	"mediapool/internal/proto"
	"mediapool/internal/relay"
	"mediapool/internal/transfer"
)

type Config struct {
	ID        string
	Addr      string // public base URL of this node's shard API
	DataDir   string
	CoordURL  string
	Heartbeat time.Duration

	Key  ed25519.PrivateKey
	Pool *auth.Pool

	// DeleteBudget caps how many shards one heartbeat may delete, so even a
	// compromised coordinator can only shrink a disk slowly.
	DeleteBudget int

	// Operator controls. Quota caps shard storage (0 = only the disk and
	// Reserve limit it); Reserve is free disk the node never fills. Upload
	// and download caps are bytes/s shared by all traffic (0 = unlimited).
	// MaxTransfers caps concurrent shard transfers. Drain asks the pool to
	// move every shard elsewhere, which is how an operator leaves cleanly.
	Quota        int64
	Reserve      int64
	UploadBps    int64
	DownloadBps  int64
	MaxTransfers int
	Drain        bool

	// Bridge settings. Source being non-nil makes this a bridge node; the
	// pool file must also grant it the bridge role.
	PoolSecret []byte
	Source     bridge.Source

	HTTP *http.Client
	Logf func(format string, args ...any)
}

type Node struct {
	cfg     Config
	id      *auth.Identity
	coord   ed25519.PublicKey
	cat     *catalog.Catalog
	reqAuth auth.Verifier

	up, down *limits.Bucket
	slots    chan struct{}
	rs       reachState

	mu          sync.Mutex
	paused      bool // test hook: simulate the node going dark
	coordURL    string
	drain       bool
	lastRefresh time.Time
	addr        string
	reach       string
	quota       int64
	upBps       int64 // current caps; the buckets enforce them
	downBps     int64
	used        int64 // bytes of shards on disk, kept current on write/delete
}

func New(cfg Config) (*Node, error) {
	if cfg.ID == "" || cfg.Addr == "" || cfg.DataDir == "" || cfg.CoordURL == "" || cfg.Key == nil || cfg.Pool == nil {
		return nil, errors.New("node: id, addr, data dir, coordinator url, key and pool are required")
	}
	if cfg.Source != nil && len(cfg.PoolSecret) == 0 {
		return nil, errors.New("node: a bridge node needs the pool secret")
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = 15 * time.Second
	}
	if cfg.DeleteBudget == 0 {
		cfg.DeleteBudget = 64
	}
	if cfg.MaxTransfers == 0 {
		cfg.MaxTransfers = 16
	}
	up, down := limits.NewBucket(cfg.UploadBps), limits.NewBucket(cfg.DownloadBps)
	if cfg.HTTP == nil {
		// Outgoing traffic (pushing rebuilt shards, fetching shards to
		// rebuild, syncing the catalog) shares the operator's caps.
		cfg.HTTP = &http.Client{Timeout: 10 * time.Minute, Transport: &limits.Transport{Up: up, Down: down}}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	coord, err := cfg.Pool.CoordinatorKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "shards"), 0o755); err != nil {
		return nil, err
	}
	cat, err := catalog.Open(filepath.Join(cfg.DataDir, "catalog.log"), coord)
	if err != nil {
		return nil, err
	}
	cfg.Pool.Attach(cat)
	n := &Node{
		cfg: cfg, id: auth.NewIdentity(cfg.Key), coord: coord, cat: cat, coordURL: cfg.CoordURL,
		up: up, down: down, slots: make(chan struct{}, cfg.MaxTransfers),
		drain: cfg.Drain, quota: cfg.Quota, addr: cfg.Addr, upBps: cfg.UploadBps, downBps: cfg.DownloadBps,
	}
	if n.used, err = n.diskUsage(); err != nil {
		return nil, err
	}
	return n, nil
}

// SetLimits changes the operator controls while running. Lowering the quota
// below current usage makes the pool move shards off this node.
func (n *Node) SetLimits(quota, uploadBps, downloadBps int64, drain bool) {
	n.mu.Lock()
	n.quota, n.drain, n.upBps, n.downBps = quota, drain, uploadBps, downloadBps
	n.mu.Unlock()
	n.up.SetRate(uploadBps)
	n.down.SetRate(downloadBps)
}

func (n *Node) diskUsage() (int64, error) {
	var total int64
	err := filepath.WalkDir(filepath.Join(n.cfg.DataDir, "shards"), func(_ string, d os.DirEntry, err error) error {
		// Count shard data only, the same bytes reserve and release track;
		// proofs and partial writes are small and not part of the quota.
		if err != nil || d.IsDir() || strings.Contains(d.Name(), ".proof") || strings.HasSuffix(d.Name(), ".tmp") {
			return err
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total, err
}

func (n *Node) info() proto.NodeInfo {
	addr, reach := n.Addr()
	return proto.NodeInfo{ID: n.cfg.ID, Addr: addr, Reach: reach, Capacity: n.Capacity()}
}

// Capacity reports what this node offers the pool right now.
func (n *Node) Capacity() proto.Capacity {
	n.mu.Lock()
	quota, used, drain, up, down := n.quota, n.used, n.drain, n.upBps, n.downBps
	n.mu.Unlock()
	avail := int64(-1)
	if free, err := diskfree.Free(n.cfg.DataDir); err == nil {
		avail = max(0, free-n.cfg.Reserve)
	}
	if quota > 0 {
		if q := max(0, quota-used); avail < 0 || q < avail {
			avail = q
		}
	}
	return proto.Capacity{
		Quota: quota, Used: used, Free: avail, Drain: drain,
		UploadBps: up, DownloadBps: down,
	}
}

// reserve claims room for size more bytes, refusing past quota or reserve.
func (n *Node) reserve(size int64) error {
	c := n.Capacity()
	if c.Drain {
		return errors.New("node is draining")
	}
	if c.Free >= 0 && size > c.Free {
		return fmt.Errorf("node is full (%s free)", limits.FormatBytes(c.Free))
	}
	n.mu.Lock()
	n.used += size
	n.mu.Unlock()
	return nil
}

func (n *Node) release(size int64) {
	n.mu.Lock()
	n.used = max(0, n.used-size)
	n.mu.Unlock()
}

// slot limits concurrent transfers; it returns false when the request
// should be refused with 503 so the caller tries another holder.
func (n *Node) slot(r *http.Request) (func(), bool) {
	select {
	case n.slots <- struct{}{}:
		return func() { <-n.slots }, true
	case <-r.Context().Done():
		return nil, false
	case <-time.After(5 * time.Second):
		return nil, false
	}
}

func (n *Node) DataDir() string           { return n.cfg.DataDir }
func (n *Node) ID() string                { return n.cfg.ID }
func (n *Node) IsBridge() bool            { return n.cfg.Source != nil }
func (n *Node) Catalog() *catalog.Catalog { return n.cat }
func (n *Node) Close() error              { return n.cat.Close() }

// SetPaused makes the node stop heartbeating and refuse requests, the way it
// would look to the pool if the machine went offline.
func (n *Node) SetPaused(p bool) {
	n.mu.Lock()
	n.paused = p
	n.mu.Unlock()
}

func (n *Node) isPaused() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.paused
}

// SetCoordURL points the node at another coordinator.
func (n *Node) SetCoordURL(u string) {
	n.mu.Lock()
	n.coordURL = u
	n.mu.Unlock()
}

// SetAddr changes the address the node advertises, and how it was
// established (see proto.NodeInfo.Reach).
func (n *Node) SetAddr(addr, reach string) {
	n.mu.Lock()
	n.addr, n.reach = addr, reach
	n.mu.Unlock()
}

func (n *Node) Addr() (addr, reach string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.addr, n.reach
}

func (n *Node) coordBase() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.coordURL
}

// --- shard store ----------------------------------------------------------

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func (n *Node) shardDir(seg string) string {
	return filepath.Join(n.cfg.DataDir, "shards", seg[:2], seg)
}

// Shards live at shards/<ab>/<segment>/<index>.<root>, with the segment-tree
// proof alongside in <index>.<root>.proof.
func (n *Node) shardPath(k proto.ShardKey) string {
	return filepath.Join(n.shardDir(k.Segment), fmt.Sprintf("%d.%s", k.Index, k.Root))
}

func (n *Node) writeShard(k proto.ShardKey, data []byte, proof string) error {
	p := n.shardPath(k)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p+".proof", []byte(proof), 0o644); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (n *Node) readShard(k proto.ShardKey) ([]byte, string, error) {
	data, err := os.ReadFile(n.shardPath(k))
	if err != nil {
		return nil, "", err
	}
	proof, err := os.ReadFile(n.shardPath(k) + ".proof")
	return data, string(proof), err
}

func (n *Node) removeShard(k proto.ShardKey) {
	p := n.shardPath(k)
	if fi, err := os.Stat(p); err == nil {
		n.release(fi.Size())
	}
	_ = os.Remove(p)
	_ = os.Remove(p + ".proof")
	_ = os.Remove(filepath.Dir(p)) // only succeeds once empty
}

// Inventory lists every shard on disk.
func (n *Node) Inventory() ([]proto.ShardKey, error) {
	var out []proto.ShardKey
	root := filepath.Join(n.cfg.DataDir, "shards")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		idxStr, rootHex, ok := strings.Cut(d.Name(), ".")
		idx, convErr := strconv.Atoi(idxStr)
		seg := filepath.Base(filepath.Dir(path))
		if ok && convErr == nil && isHex64(seg) && isHex64(rootHex) {
			out = append(out, proto.ShardKey{Segment: seg, Index: idx, Root: rootHex})
		}
		return nil
	})
	return out, err
}

// --- HTTP API -------------------------------------------------------------

func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/shards/{seg}/{idx}", n.handleGet)
	mux.HandleFunc("PUT /v1/shards/{seg}/{idx}", n.handlePut)
	mux.HandleFunc("GET /v1/proof/{seg}/{idx}", n.handleProof)
	mux.HandleFunc("GET /v1/ping", n.handlePing)
	mux.HandleFunc("GET /v1/log", n.authed(n.cat.ServeLog))
	return mux
}

// authed admits only requests signed by a pool member, node or coordinator.
func (n *Node) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if n.isPaused() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		pub, err := n.reqAuth.VerifyURI(r, signedURI(r), nil)
		if err == nil && !n.known(r.Context(), pub) {
			err = errors.New("not a pool participant")
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// known reports whether pub belongs to the pool, catching up on the catalog
// once if it might belong to someone who just joined.
func (n *Node) known(ctx context.Context, pub ed25519.PublicKey) bool {
	if pub.Equal(n.coord) {
		return true
	}
	if _, ok := n.cfg.Pool.Lookup(pub); ok {
		return true
	}
	if !n.refreshMembership(ctx) {
		return false
	}
	_, ok := n.cfg.Pool.Lookup(pub)
	return ok
}

// refreshMembership pulls new catalog entries when a validly signed request
// comes from a key this node doesn't know yet, typically a member who
// joined since the last heartbeat. At most once every few seconds, so
// strangers can't make the node hammer the coordinator. It reports whether
// anything new arrived.
func (n *Node) refreshMembership(ctx context.Context) bool {
	n.mu.Lock()
	if time.Since(n.lastRefresh) < 3*time.Second {
		n.mu.Unlock()
		return false
	}
	n.lastRefresh = time.Now()
	n.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	got, err := n.cat.Sync(ctx, n.cfg.HTTP, n.coordBase(), n.id.Signer())
	return err == nil && got > 0
}

// signedURI is the URI the sender signed. Behind a relay that's the
// relay's longer URI, which must end with the path the node received.
func signedURI(r *http.Request) string {
	uri := r.URL.RequestURI()
	if orig := r.Header.Get(relay.OriginalURIHeader); orig != "" && strings.HasSuffix(orig, uri) {
		return orig
	}
	return uri
}

// handlePing answers the coordinator's reachability probe, proving this
// address really leads to this node.
func (n *Node) handlePing(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if len(nonce) < 16 || len(nonce) > 128 || n.isPaused() {
		http.Error(w, "bad ping", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.PingResponse{ID: n.cfg.ID, Sig: ed25519.Sign(n.cfg.Key, proto.PingSigMessage(n.cfg.ID, nonce))})
}

func parseKey(r *http.Request, rootHex string) (proto.ShardKey, error) {
	seg := r.PathValue("seg")
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if !isHex64(seg) || err != nil || idx < 0 || idx > 255 || !isHex64(rootHex) {
		return proto.ShardKey{}, errors.New("bad shard key")
	}
	return proto.ShardKey{Segment: seg, Index: idx, Root: rootHex}, nil
}

func (n *Node) handleGet(w http.ResponseWriter, r *http.Request) {
	n.authed(func(w http.ResponseWriter, r *http.Request) {
		k, err := parseKey(r, r.URL.Query().Get("root"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, proof, err := n.readShard(k)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		done, ok := n.slot(r)
		if !ok {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		defer done()
		w.Header().Set(transfer.ProofHeader, proof)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = limits.Writer{Ctx: r.Context(), W: w, B: n.up}.Write(data)
	})(w, r)
}

// handlePut stores a shard only if the coordinator issued a ticket for this
// exact shard on this node and the data verifies against the ticket's root.
// Shards are stored under their root, so a valid-looking upload for another
// root can never replace committed data.
func (n *Node) handlePut(w http.ResponseWriter, r *http.Request) {
	if n.isPaused() {
		http.Error(w, "offline", http.StatusServiceUnavailable)
		return
	}
	var t proto.Ticket
	tb, err := base64.StdEncoding.DecodeString(r.Header.Get(transfer.TicketHeader))
	if err == nil {
		err = json.Unmarshal(tb, &t)
	}
	if err != nil {
		http.Error(w, "missing or malformed upload ticket", http.StatusForbidden)
		return
	}
	k, err := parseKey(r, t.Root)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := t.Check(n.coord, n.cfg.ID, k.Segment, k.Index, time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	limit := int64(codec.ShardSize(t.Params(), t.CipherSize))
	if _, err := os.Stat(n.shardPath(k)); err == nil {
		io.Copy(io.Discard, io.LimitReader(r.Body, limit))
		w.WriteHeader(http.StatusCreated) // already have it
		return
	}
	if err := n.reserve(limit); err != nil {
		http.Error(w, err.Error(), http.StatusInsufficientStorage)
		return
	}
	stored := false
	defer func() {
		if !stored {
			n.release(limit)
		}
	}()
	done, ok := n.slot(r)
	if !ok {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	defer done()
	body := &throttled{ctx: r.Context(), r: http.MaxBytesReader(w, r.Body, limit), b: n.down}
	data, err := io.ReadAll(body)
	if err != nil || int64(len(data)) != limit {
		http.Error(w, "shard has the wrong size", http.StatusBadRequest)
		return
	}
	root, _ := codec.HexToHash(t.Root)
	proofHdr := r.Header.Get(transfer.ProofHeader)
	proof, err := codec.DecodeProof(proofHdr)
	if err != nil || !codec.VerifyShard(root, t.MaxN, k.Index, data, proof) {
		http.Error(w, "shard doesn't verify against the segment root", http.StatusBadRequest)
		return
	}
	if err := n.writeShard(k, data, proofHdr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stored = true
	w.WriteHeader(http.StatusCreated)
}

type throttled struct {
	ctx context.Context
	r   io.Reader
	b   *limits.Bucket
}

func (t *throttled) Read(p []byte) (int, error) {
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	m, err := t.r.Read(p)
	if m > 0 {
		if werr := t.b.Wait(t.ctx, m); werr != nil {
			return m, werr
		}
	}
	return m, err
}

// handleProof answers a storage challenge: chunk c of a shard with Merkle
// proofs up to the segment root, signed over the coordinator's nonce.
func (n *Node) handleProof(w http.ResponseWriter, r *http.Request) {
	if n.isPaused() {
		http.Error(w, "offline", http.StatusServiceUnavailable)
		return
	}
	pub, err := n.reqAuth.VerifyURI(r, signedURI(r), nil)
	if err != nil || !pub.Equal(n.coord) {
		http.Error(w, "only the coordinator issues challenges", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	k, err := parseKey(r, q.Get("root"))
	chunk, cerr := strconv.Atoi(q.Get("chunk"))
	nonce := q.Get("nonce")
	if err != nil || cerr != nil || len(nonce) < 16 {
		http.Error(w, "bad challenge", http.StatusBadRequest)
		return
	}
	data, segProof, err := n.readShard(k)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, cp, err := codec.ChunkProof(data, chunk)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := proto.ProofResponse{
		ShardHash:  codec.HashToHex(codec.ShardHash(data)),
		SegProof:   segProof,
		Chunk:      c,
		ChunkProof: codec.EncodeProof(cp),
		Sig:        ed25519.Sign(n.cfg.Key, proto.ProofSigMessage(nonce, k.Segment, k.Index, k.Root, chunk, c)),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// --- coordinator loop -----------------------------------------------------

// Run heartbeats until ctx is done.
func (n *Node) Run(ctx context.Context) {
	t := time.NewTicker(n.cfg.Heartbeat)
	defer t.Stop()
	for {
		if !n.isPaused() {
			if err := n.HeartbeatOnce(ctx); err != nil && ctx.Err() == nil {
				n.cfg.Logf("heartbeat: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (n *Node) HeartbeatOnce(ctx context.Context) error {
	base := n.coordBase()
	if _, err := n.cat.Sync(ctx, n.cfg.HTTP, base, n.id.Signer()); err != nil {
		// Keep heartbeating so the coordinator can catch up from us; a fork
		// is logged loudly and never resolved by rewriting our replica.
		n.cfg.Logf("catalog sync from coordinator: %v", err)
	}
	inv, err := n.Inventory()
	if err != nil {
		return err
	}
	req := proto.HeartbeatRequest{
		Node:      n.info(),
		Head:      n.cat.Head(),
		Inventory: inv,
	}
	resp, err := n.heartbeat(ctx, base, req)
	if err != nil {
		return err
	}
	n.applyDeletes(resp.Deletes, inv)
	if !resp.Ready {
		return nil // a recovering coordinator: don't act on its tasks yet
	}
	for _, t := range resp.Tasks {
		go n.runTask(ctx, t)
	}
	for _, hc := range resp.HealthChecks {
		go n.checkSwarm(ctx, hc)
	}
	return nil
}

// heartbeat sends a signed heartbeat and verifies the coordinator's
// signature on the response before anything in it is acted on.
func (n *Node) heartbeat(ctx context.Context, base string, in proto.HeartbeatRequest) (proto.HeartbeatResponse, error) {
	var out proto.HeartbeatResponse
	body, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/heartbeat", strings.NewReader(string(body)))
	if err != nil {
		return out, err
	}
	n.id.Sign(req, body)
	resp, err := n.cfg.HTTP.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("heartbeat: %s: %s", resp.Status, strings.TrimSpace(string(rb)))
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Header.Get(proto.CoordSigHeader))
	if err != nil || !ed25519.Verify(n.coord, proto.HeartbeatSigMessage(n.cfg.ID, rb), sig) {
		return out, errors.New("heartbeat response not signed by the coordinator")
	}
	return out, json.Unmarshal(rb, &out)
}

// applyDeletes removes shards the coordinator asked to drop, but only when
// this node's own catalog replica agrees it's safe: the segment has been
// collected, or the shard belongs to an upload that was never committed, or
// it's a surplus copy of a committed shard (which the coordinator can only
// request a few at a time). Anything else is refused and logged.
func (n *Node) applyDeletes(dels []proto.ShardKey, inv []proto.ShardKey) {
	have := make(map[proto.ShardKey]bool, len(inv))
	for _, k := range inv {
		have[k] = true
	}
	budget := n.cfg.DeleteBudget
	for _, k := range dels {
		if !have[k] || !isHex64(k.Segment) {
			continue
		}
		seg, known := n.cat.Segment(k.Segment)
		switch {
		case known && !seg.Live(), known && seg.ShardRoot != k.Root:
			n.removeShard(k) // collected, or junk under a committed ID: free
		case !known:
			// Our replica may be behind the coordinator; never delete what we
			// can't account for.
			n.cfg.Logf("refusing delete of %.12s/%d: segment not in our catalog", k.Segment, k.Index)
		case budget > 0:
			budget--
			n.removeShard(k)
		default:
			n.cfg.Logf("delete budget spent; deferring %.12s/%d", k.Segment, k.Index)
		}
	}
}

func (n *Node) runTask(ctx context.Context, t proto.Task) {
	res := proto.TaskResult{TaskID: t.ID}
	placed, err := n.execute(ctx, t)
	res.Placed = placed
	if err != nil {
		res.Error = err.Error()
		n.cfg.Logf("task %s (%.12s): %v", t.ID, t.Segment, err)
	}
	if err := transfer.PostJSON(ctx, n.cfg.HTTP, n.id, n.coordBase()+"/v1/task-result", res, nil); err != nil {
		n.cfg.Logf("report task %s: %v", t.ID, err)
	}
}

func (n *Node) execute(ctx context.Context, t proto.Task) ([]proto.Location, error) {
	root, err := codec.HexToHash(t.Root)
	if err != nil {
		return nil, err
	}
	if t.Move != nil {
		return n.move(ctx, t, root)
	}
	var shards [][]byte
	if t.SourceBlob != nil {
		shards, err = n.rebuildFromSwarm(ctx, t)
	} else {
		shards, err = n.rebuildFromPool(ctx, t, root)
	}
	if err != nil {
		return nil, err
	}
	tree := codec.NewTree(shards)
	if tree.Root != root {
		return nil, errors.New("rebuilt segment doesn't match its root")
	}
	var placed []proto.Location
	var errs []error
	for _, p := range t.Put {
		if p.Index < 0 || p.Index >= len(shards) {
			continue
		}
		if err := transfer.PutShard(ctx, n.cfg.HTTP, p.Addr, t.Segment, p.Index, shards[p.Index], tree.Proof(p.Index), &p.Ticket); err != nil {
			errs = append(errs, err)
			continue
		}
		placed = append(placed, p.Location)
	}
	return placed, errors.Join(errs...)
}

// move copies one shard from a leaving node to the task's target (usually
// this node), verifying it against the segment root on the way.
func (n *Node) move(ctx context.Context, t proto.Task, root [32]byte) ([]proto.Location, error) {
	if len(t.Put) != 1 || t.Put[0].Index != t.Move.Index {
		return nil, errors.New("malformed move task")
	}
	data, proof, err := transfer.GetShard(ctx, n.cfg.HTTP, n.id, t.Move.Addr, t.Segment, t.Move.Index, t.Root)
	if err != nil {
		return nil, err
	}
	if !codec.VerifyShard(root, t.Params.MaxN, t.Move.Index, data, proof) {
		return nil, errors.New("moved shard doesn't verify")
	}
	p := t.Put[0]
	if err := transfer.PutShard(ctx, n.cfg.HTTP, p.Addr, t.Segment, p.Index, data, proof, &p.Ticket); err != nil {
		return nil, err
	}
	return []proto.Location{p.Location}, nil
}

func (n *Node) rebuildFromPool(ctx context.Context, t proto.Task, root [32]byte) ([][]byte, error) {
	shards, err := transfer.FetchAny(ctx, n.cfg.HTTP, n.id, t.Segment, t.Fetch, root, t.Params.K, t.Params.MaxN)
	if err != nil {
		return nil, err
	}
	if err := codec.Reconstruct(t.Params, shards); err != nil {
		return nil, err
	}
	return shards, nil
}

// fromSwarm re-derives a segment from its original torrent: fetch the
// plaintext range, re-encrypt with the convergent key and check it hashes to
// the segment ID. The torrent's own piece hashes (SHA-1 in v1) aren't relied
// on.
func (n *Node) fromSwarm(ctx context.Context, blob []byte, segID string) ([]byte, error) {
	if !n.IsBridge() {
		return nil, errors.New("not a bridge node")
	}
	ref, err := bridge.OpenRef(n.cfg.PoolSecret, blob)
	if err != nil {
		return nil, fmt.Errorf("open source ref: %w", err)
	}
	plain, err := n.cfg.Source.ReadRange(ctx, ref)
	if err != nil {
		return nil, err
	}
	_, ct, id, err := codec.SealSegment(n.cfg.PoolSecret, plain)
	if err != nil {
		return nil, err
	}
	if id != segID {
		return nil, fmt.Errorf("swarm bytes from %s don't rebuild segment %.12s", ref.Infohash, segID)
	}
	return ct, nil
}

func (n *Node) rebuildFromSwarm(ctx context.Context, t proto.Task) ([][]byte, error) {
	ct, err := n.fromSwarm(ctx, t.SourceBlob, t.Segment)
	if err != nil {
		return nil, err
	}
	if len(ct) != t.CipherSize {
		return nil, errors.New("swarm segment has the wrong size")
	}
	return codec.Encode(t.Params, ct)
}

// checkSwarm reports on a segment's external source. A verify check rebuilds
// the segment from the swarm and only reports healthy on an exact match, so
// a member can't anchor a segment to a torrent that doesn't contain it.
func (n *Node) checkSwarm(ctx context.Context, hc proto.HealthCheck) {
	rep := proto.SwarmReport{Segment: hc.Segment}
	if hc.Verify {
		_, err := n.fromSwarm(ctx, hc.SourceBlob, hc.Segment)
		rep.Healthy, rep.Verified = err == nil, err == nil
		if err != nil {
			n.cfg.Logf("verify %.12s: %v", hc.Segment, err)
		}
	} else {
		ref, err := bridge.OpenRef(n.cfg.PoolSecret, hc.SourceBlob)
		if err == nil {
			rep.Healthy, err = n.cfg.Source.Healthy(ctx, ref)
		}
		if err != nil {
			n.cfg.Logf("health check %.12s: %v", hc.Segment, err)
		}
	}
	if err := transfer.PostJSON(ctx, n.cfg.HTTP, n.id, n.coordBase()+"/v1/swarm-report", rep, nil); err != nil {
		n.cfg.Logf("swarm report: %v", err)
	}
}
