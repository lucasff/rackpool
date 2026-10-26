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
	"mediapool/internal/proto"
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

	mu       sync.Mutex
	paused   bool // test hook: simulate the node going dark
	coordURL string
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
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 2 * time.Minute}
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
	cat, err := catalog.Open(filepath.Join(cfg.DataDir, "catalog.log"), coord, cfg.Pool.MemberKey)
	if err != nil {
		return nil, err
	}
	return &Node{cfg: cfg, id: auth.NewIdentity(cfg.Key), coord: coord, cat: cat, coordURL: cfg.CoordURL}, nil
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
		pub, err := n.reqAuth.Verify(r, nil)
		if err == nil {
			if _, ok := n.cfg.Pool.Lookup(pub); !ok && !pub.Equal(n.coord) {
				err = errors.New("not a pool participant")
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
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
		w.Header().Set(transfer.ProofHeader, proof)
		_, _ = w.Write(data)
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
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
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
	w.WriteHeader(http.StatusCreated)
}

// handleProof answers a storage challenge: chunk c of a shard with Merkle
// proofs up to the segment root, signed over the coordinator's nonce.
func (n *Node) handleProof(w http.ResponseWriter, r *http.Request) {
	if n.isPaused() {
		http.Error(w, "offline", http.StatusServiceUnavailable)
		return
	}
	body := []byte(nil)
	pub, err := n.reqAuth.Verify(r, body)
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
		Node:      proto.NodeInfo{ID: n.cfg.ID, Addr: n.cfg.Addr},
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
