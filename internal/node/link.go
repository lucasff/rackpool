package node

// Linked segments (prototype).
//
// A node can link a file from its own disk into the pool instead of
// uploading it. Encryption is convergent and erasure coding is
// deterministic, so a node that holds a segment's plaintext can regenerate
// any of its shards, with the same Merkle proof, byte for byte. A linked
// segment therefore needs no stored shards: readShard rebuilds them on
// request, and every shard API (whole shards, chunks, storage proofs) works
// unchanged. Readers can't tell a linked shard from a stored one.
//
// The node keeps a small index, links.json in its data dir, from segment ID
// to the file range it came from. Only files under Config.LinkRoot can be
// linked. Regenerating needs the pool secret.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"mediapool/internal/codec"
	"mediapool/internal/proto"
)

// linkRef is where a linked segment's plaintext lives on this node's disk.
type linkRef struct {
	Path       string `json:"path"` // relative to LinkRoot
	Offset     int64  `json:"offset"`
	Length     int64  `json:"length"`
	Root       string `json:"root"`
	CipherSize int    `json:"cipher_size"`
}

// linkedSeg is a regenerated segment kept briefly in memory. Readers fetch
// the k data shards in parallel, so one regeneration serves all of them.
// Parity shards aren't kept; they're rebuilt on the rare request for one.
type linkedSeg struct {
	data   [][]byte // the k data shards
	proofs []string // segment-tree proof for every index, len max_n
}

type linkCall struct {
	done chan struct{}
	seg  *linkedSeg
	err  error
}

// links holds the link index and the regeneration cache.
type links struct {
	mu       sync.Mutex
	refs     map[string]linkRef
	cache    map[string]*linkedSeg
	order    []string // cache LRU, oldest first
	inflight map[string]*linkCall
}

const linkCacheSegments = 4

func (n *Node) linksPath() string { return filepath.Join(n.cfg.DataDir, "links.json") }

func (n *Node) loadLinks() error {
	n.links = links{refs: map[string]linkRef{}, cache: map[string]*linkedSeg{}, inflight: map[string]*linkCall{}}
	b, err := os.ReadFile(n.linksPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &n.links.refs)
}

// saveLinks writes the index. Caller holds n.links.mu.
func (n *Node) saveLinks() error {
	b, err := json.MarshalIndent(n.links.refs, "", " ")
	if err != nil {
		return err
	}
	tmp := n.linksPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, n.linksPath())
}

// LinkRoot is the directory this node may link files from ("" = linking off).
func (n *Node) LinkRoot() string { return n.cfg.LinkRoot }

// resolveLink turns a path under LinkRoot into the relative form stored in
// the index, refusing anything outside it.
func (n *Node) resolveLink(p string) (rel string, err error) {
	if n.cfg.LinkRoot == "" {
		return "", errors.New("linking is off: start the node with a link root")
	}
	root, err := filepath.Abs(n.cfg.LinkRoot)
	if err != nil {
		return "", err
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, p)
	}
	rel, err = filepath.Rel(root, filepath.Clean(abs))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the link root %s", p, root)
	}
	return rel, nil
}

// AddLink registers one segment of a local file. It regenerates the segment
// from disk first and checks it matches the claimed ID and root, so the
// index never points at bytes that would fail verification.
func (n *Node) AddLink(seg, root string, cipherSize int, path string, offset, length int64) error {
	if len(n.cfg.PoolSecret) == 0 {
		return errors.New("linking needs the pool secret (MEDIAPOOL_SECRET)")
	}
	rel, err := n.resolveLink(path)
	if err != nil {
		return err
	}
	ref := linkRef{Path: rel, Offset: offset, Length: length, Root: root, CipherSize: cipherSize}
	if _, err := n.regenerate(seg, ref); err != nil {
		return err
	}
	n.links.mu.Lock()
	defer n.links.mu.Unlock()
	n.links.refs[seg] = ref
	return n.saveLinks()
}

// unlink forgets a segment, once the pool has collected it.
func (n *Node) unlink(seg string) {
	n.links.mu.Lock()
	defer n.links.mu.Unlock()
	if _, ok := n.links.refs[seg]; !ok {
		return
	}
	delete(n.links.refs, seg)
	delete(n.links.cache, seg)
	n.links.order = slices.DeleteFunc(n.links.order, func(s string) bool { return s == seg })
	if err := n.saveLinks(); err != nil {
		n.cfg.Logf("unlink %.12s: %v", seg, err)
	}
}

// Links returns how many segments this node serves from local files.
func (n *Node) Links() int {
	n.links.mu.Lock()
	defer n.links.mu.Unlock()
	return len(n.links.refs)
}

func (n *Node) linkRef(seg string) (linkRef, bool) {
	n.links.mu.Lock()
	defer n.links.mu.Unlock()
	r, ok := n.links.refs[seg]
	return r, ok
}

// linkInventory reports the data shards of every linked segment. Those are
// the ones readers need; parity is regenerated only if asked for.
func (n *Node) linkInventory() []proto.ShardKey {
	cfg, ok := n.cat.Config()
	if !ok {
		return nil
	}
	n.links.mu.Lock()
	defer n.links.mu.Unlock()
	out := make([]proto.ShardKey, 0, len(n.links.refs)*cfg.K)
	for seg, r := range n.links.refs {
		for i := range cfg.K {
			out = append(out, proto.ShardKey{Segment: seg, Index: i, Root: r.Root})
		}
	}
	return out
}

// readLinked returns shard k of a linked segment and its segment-tree proof.
func (n *Node) readLinked(k proto.ShardKey) ([]byte, string, error) {
	ref, ok := n.linkRef(k.Segment)
	if !ok || ref.Root != k.Root {
		return nil, "", os.ErrNotExist
	}
	cfg, ok := n.cat.Config()
	if !ok {
		return nil, "", errors.New("no pool config in the catalog yet")
	}
	if k.Index >= cfg.MaxN {
		return nil, "", os.ErrNotExist
	}
	ls, err := n.cachedLinked(k.Segment, ref)
	if err != nil {
		return nil, "", err
	}
	if k.Index < cfg.K {
		return ls.data[k.Index], ls.proofs[k.Index], nil
	}
	shards, err := n.encodeLinked(k.Segment, ref) // parity: rare, not cached
	if err != nil {
		return nil, "", err
	}
	return shards[k.Index], ls.proofs[k.Index], nil
}

// cachedLinked regenerates a segment at most once at a time and keeps the
// last few, so the k parallel shard reads of one segment share the work.
func (n *Node) cachedLinked(seg string, ref linkRef) (*linkedSeg, error) {
	l := &n.links
	l.mu.Lock()
	if ls, ok := l.cache[seg]; ok {
		l.order = append(slices.DeleteFunc(l.order, func(s string) bool { return s == seg }), seg)
		l.mu.Unlock()
		return ls, nil
	}
	if c, ok := l.inflight[seg]; ok {
		l.mu.Unlock()
		<-c.done
		return c.seg, c.err
	}
	c := &linkCall{done: make(chan struct{})}
	l.inflight[seg] = c
	l.mu.Unlock()

	c.seg, c.err = n.regenerate(seg, ref)

	l.mu.Lock()
	delete(l.inflight, seg)
	if c.err == nil {
		l.cache[seg] = c.seg
		l.order = append(l.order, seg)
		for len(l.order) > linkCacheSegments {
			delete(l.cache, l.order[0])
			l.order = l.order[1:]
		}
	}
	l.mu.Unlock()
	close(c.done)
	return c.seg, c.err
}

// encodeLinked reads a segment's plaintext, seals and erasure-codes it,
// checking the result is the segment the pool knows.
func (n *Node) encodeLinked(seg string, ref linkRef) ([][]byte, error) {
	cfg, ok := n.cat.Config()
	if !ok {
		return nil, errors.New("no pool config in the catalog yet")
	}
	f, err := os.Open(filepath.Join(n.cfg.LinkRoot, ref.Path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	plain := make([]byte, ref.Length)
	if _, err := f.ReadAt(plain, ref.Offset); err != nil && !(errors.Is(err, io.EOF) && ref.Length == 0) {
		return nil, fmt.Errorf("read %s: %w", ref.Path, err)
	}
	_, ct, id, err := codec.SealSegment(n.cfg.PoolSecret, plain)
	if err != nil {
		return nil, err
	}
	if id != seg {
		return nil, fmt.Errorf("%s changed on disk: segment %.12s no longer matches", ref.Path, seg)
	}
	return codec.Encode(codec.Params{K: cfg.K, MaxN: cfg.MaxN}, ct)
}

func (n *Node) regenerate(seg string, ref linkRef) (*linkedSeg, error) {
	shards, err := n.encodeLinked(seg, ref)
	if err != nil {
		return nil, err
	}
	tree := codec.NewTree(shards)
	if codec.HashToHex(tree.Root) != ref.Root {
		return nil, fmt.Errorf("segment %.12s doesn't encode to its root", seg)
	}
	cfg, _ := n.cat.Config()
	// Clone so the parity buffers aren't kept alive by the slice's capacity.
	ls := &linkedSeg{data: slices.Clone(shards[:cfg.K]), proofs: make([]string, len(shards))}
	for i := range shards {
		ls.proofs[i] = codec.EncodeProof(tree.Proof(i))
	}
	return ls, nil
}
