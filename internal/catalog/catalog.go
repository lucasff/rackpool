// Package catalog is the pool's durable metadata: an append-only,
// hash-chained log of signed entries, and the state derived by replaying it.
// Shard locations, node liveness and heat are not in here: they are soft
// state the coordinator rebuilds from heartbeats.
//
// The coordinator is the log's only writer, signing with its own key, but
// not its only holder. Every node and client keeps a verified replica, so a
// coordinator that loses its disk catches up from any node.
package catalog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrFork means an entry doesn't extend the local log: the two copies
	// have diverged, or the sender is behind.
	ErrFork = errors.New("catalog: entry doesn't extend the local log")
	// ErrInvalid means an entry is badly signed or breaks the catalog rules.
	ErrInvalid = errors.New("catalog: invalid entry")
)

const pageSize = 1000

type Head struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash,omitempty"`
}

type Entry struct {
	Seq    uint64          `json:"seq"`
	Prev   string          `json:"prev"`
	TimeMs int64           `json:"time_ms"`
	Type   string          `json:"type"`
	Body   json.RawMessage `json:"body"`
	Sig    []byte          `json:"sig"`
}

func (e *Entry) signedBytes() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "mediapool/catalog/v1\n%d\n%s\n%d\n%d:%s\n", e.Seq, e.Prev, e.TimeMs, len(e.Type), e.Type)
	b.Write(e.Body)
	return b.Bytes()
}

// Hash identifies an entry; the next entry's Prev must equal it.
func (e *Entry) Hash() string {
	s := sha256.Sum256(e.signedBytes())
	return hex.EncodeToString(s[:])
}

type Catalog struct {
	pub ed25519.PublicKey

	mu      sync.Mutex
	entries []Entry
	head    Head
	file    *os.File
	state   state
}

// Open loads and verifies the log at path, or starts an empty in-memory log
// when path is "". coord is the coordinator's public key; members resolves
// file authors. A torn final line left by a crash mid-append is dropped.
func Open(path string, coord ed25519.PublicKey, members MemberKeys) (*Catalog, error) {
	c := &Catalog{pub: coord, state: newState(members)}
	if path == "" {
		return c, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Catalog, error) {
		f.Close()
		return nil, fmt.Errorf("catalog: %s: %w", path, err)
	}
	r := bufio.NewReader(f)
	var good int64
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			break // anything left in line is a torn write
		}
		if err != nil {
			return fail(err)
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fail(fmt.Errorf("entry %d: %w", c.head.Seq+1, err))
		}
		if err := c.ingest(e); err != nil {
			return fail(err)
		}
		good += int64(len(line))
	}
	if err := f.Truncate(good); err != nil {
		return fail(err)
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		return fail(err)
	}
	c.file = f
	return c, nil
}

func (c *Catalog) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	return c.file.Close()
}

// ingest verifies, persists and applies one entry. Caller holds c.mu.
func (c *Catalog) ingest(e Entry) error {
	if e.Seq <= c.head.Seq && e.Seq > 0 {
		if c.entries[e.Seq-1].Hash() == e.Hash() {
			return nil // already have it (a concurrent sync got there first)
		}
		return fmt.Errorf("%w: entry %d differs from ours", ErrFork, e.Seq)
	}
	if e.Seq != c.head.Seq+1 || e.Prev != c.head.Hash {
		return fmt.Errorf("%w: got entry %d after %.12s, local head is %d %.12s", ErrFork, e.Seq, e.Prev, c.head.Seq, c.head.Hash)
	}
	if !ed25519.Verify(c.pub, e.signedBytes(), e.Sig) {
		return fmt.Errorf("%w: entry %d: bad signature", ErrInvalid, e.Seq)
	}
	commit, err := c.state.apply(&e)
	if err != nil {
		return fmt.Errorf("%w: entry %d (%s): %v", ErrInvalid, e.Seq, e.Type, err)
	}
	if c.file != nil {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := c.file.Write(append(b, '\n')); err != nil {
			return err
		}
		if err := c.file.Sync(); err != nil {
			return err
		}
	}
	commit()
	c.entries = append(c.entries, e)
	c.head = Head{Seq: e.Seq, Hash: e.Hash()}
	return nil
}

// Append signs and appends a new entry. Only the coordinator calls it.
func (c *Catalog) Append(priv ed25519.PrivateKey, typ string, body any) (Entry, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return Entry{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := Entry{Seq: c.head.Seq + 1, Prev: c.head.Hash, TimeMs: time.Now().UnixMilli(), Type: typ, Body: b}
	e.Sig = ed25519.Sign(priv, e.signedBytes())
	return e, c.ingest(e)
}

// Ingest appends entries received from another replica, returning how many
// were new.
func (c *Catalog) Ingest(entries []Entry) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range entries {
		before := c.head.Seq
		if err := c.ingest(e); err != nil {
			return n, err
		}
		if c.head.Seq > before {
			n++
		}
	}
	return n, nil
}

// Sync pulls every entry past the local head from another replica's
// /v1/log endpoint (the coordinator or any node). sign, if non-nil,
// authenticates each request. Entries are verified against the coordinator
// key, so the replica serving them doesn't have to be trusted.
func (c *Catalog) Sync(ctx context.Context, hc *http.Client, baseURL string, sign func(*http.Request)) (int, error) {
	total := 0
	for {
		url := fmt.Sprintf("%s/v1/log?from=%d&limit=%d", baseURL, c.Head().Seq+1, pageSize)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return total, err
		}
		if sign != nil {
			sign(req)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return total, err
		}
		var page []Entry
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return total, fmt.Errorf("catalog: sync from %s: %s: %s", baseURL, resp.Status, strings.TrimSpace(string(b)))
		}
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return total, err
		}
		if len(page) == 0 {
			return total, nil
		}
		n, err := c.Ingest(page)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil // nothing new: don't spin on a misbehaving peer
		}
	}
}

// ServeLog answers GET /v1/log?from=N&limit=M with entries starting at seq N.
func (c *Catalog) ServeLog(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if from == 0 {
		from = 1
	}
	if limit <= 0 || limit > pageSize {
		limit = pageSize
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.Entries(from, limit))
}

func (c *Catalog) Entries(from uint64, limit int) []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []Entry{}
	if from == 0 || from > uint64(len(c.entries)) {
		return out
	}
	end := min(int(from-1)+limit, len(c.entries))
	return append(out, c.entries[from-1:end]...)
}

// HashAt returns the hash of entry seq, or "" if the log is shorter.
func (c *Catalog) HashAt(seq uint64) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seq == 0 || seq > uint64(len(c.entries)) {
		return ""
	}
	return c.entries[seq-1].Hash()
}

func (c *Catalog) Head() Head {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}

// Segment returns the record for id, including tombstoned segments.
func (c *Catalog) Segment(id string) (Segment, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.state.segments[id]
	if !ok {
		return Segment{}, false
	}
	return *s, true
}

// LiveSegments returns every non-tombstoned segment, sorted by ID.
func (c *Catalog) LiveSegments() []Segment {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Segment, 0, len(c.state.segments))
	for _, s := range c.state.segments {
		if s.Live() {
			out = append(out, *s)
		}
	}
	slices.SortFunc(out, func(a, b Segment) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (c *Catalog) File(pathID string) (File, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.state.files[pathID]
	if !ok {
		return File{}, false
	}
	return *f, true
}

func (c *Catalog) Files() []File {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]File, 0, len(c.state.files))
	for _, f := range c.state.files {
		out = append(out, *f)
	}
	return out
}

func (c *Catalog) FileCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.state.files)
}
