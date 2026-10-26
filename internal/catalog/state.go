package catalog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"mediapool/internal/auth"
)

// Entry types. Every body holds only ciphertext facts and sealed blobs.
const (
	TypeSegmentAdd    = "segment.add"
	TypeSegmentSource = "segment.source"
	TypeSegmentSwarm  = "segment.swarm" // logged on transitions only
	TypeSegmentGC     = "segment.gc"    // the only way shards are ever deleted for good
	TypeFilePut       = "file.put"
	TypeFileDel       = "file.del"
)

const (
	SwarmUnknown = ""
	SwarmHealthy = "healthy"
	SwarmDead    = "dead"
)

type SegmentAdd struct {
	ID         string `json:"id"` // hash of the segment ciphertext
	CipherSize int    `json:"cipher_size"`
	ShardRoot  string `json:"shard_root"`       // Merkle root over the segment's shard hashes
	Source     []byte `json:"source,omitempty"` // sealed torrent source reference
}

type SegmentSource struct {
	ID     string `json:"id"`
	Source []byte `json:"source"`
}

type SegmentSwarm struct {
	ID      string `json:"id"`
	Healthy bool   `json:"healthy"`
}

type SegmentGC struct {
	ID string `json:"id"`
}

// FilePut names the segments in clear so the catalog can count references;
// the manifest itself (path, sizes, keys) stays sealed. It is signed by its
// author, so the coordinator can order file changes but can't forge them:
// only the author can overwrite or delete a file, and a segment can only be
// collected once no file references it. Replaces is the seq of the entry
// being overwritten (0 for a new path), which stops old signed entries from
// being replayed.
type FilePut struct {
	PathID   string   `json:"path_id"`
	Author   string   `json:"author"`
	Replaces uint64   `json:"replaces"`
	Segments []string `json:"segments"`
	Manifest []byte   `json:"manifest"`
	Sig      []byte   `json:"sig"`
}

func (b *FilePut) Message() []byte {
	h := sha256.Sum256(b.Manifest)
	return fmt.Appendf(nil, "mediapool/file-put/v1\n%s\n%s\n%d\n%s\n%x",
		b.PathID, b.Author, b.Replaces, strings.Join(b.Segments, ","), h)
}

type FileDel struct {
	PathID   string `json:"path_id"`
	Author   string `json:"author"`
	Replaces uint64 `json:"replaces"`
	Sig      []byte `json:"sig"`
}

func (b *FileDel) Message() []byte {
	return fmt.Appendf(nil, "mediapool/file-del/v1\n%s\n%s\n%d", b.PathID, b.Author, b.Replaces)
}

type Segment struct {
	SegmentAdd
	Swarm         string `json:"swarm"`
	Refs          int    `json:"refs"`
	RefsChangedMs int64  `json:"refs_changed_ms"`
	GCAtMs        int64  `json:"gc_at_ms,omitempty"` // non-zero once tombstoned
}

func (s Segment) Live() bool { return s.GCAtMs == 0 }

type File struct {
	FilePut
	Seq uint64 `json:"seq"` // entry that last wrote it
}

type state struct {
	config   *PoolConfig
	m        membership
	segments map[string]*Segment
	files    map[string]*File
}

func newState() state {
	return state{
		m:        membership{members: map[string]auth.Member{}, nodes: map[string]auth.NodeEntry{}, invites: map[string]*invite{}},
		segments: map[string]*Segment{}, files: map[string]*File{},
	}
}

func (s *state) live(id string) (*Segment, error) {
	seg := s.segments[id]
	if seg == nil || !seg.Live() {
		return nil, fmt.Errorf("segment %.12s is not live", id)
	}
	return seg, nil
}

func (s *state) ref(ids []string, delta int, atMs int64) {
	for _, id := range ids {
		seg := s.segments[id]
		seg.Refs += delta
		seg.RefsChangedMs = atMs
	}
}

func (s *state) checkAuthor(author string, msg, sig []byte) error {
	var pub ed25519.PublicKey
	if m, ok := s.m.member(author); ok {
		pub, _ = hex.DecodeString(m.Key)
	}
	if pub == nil {
		return fmt.Errorf("author %q is not a member", author)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("bad signature from %q", author)
	}
	return nil
}

// checkOwner enforces that only a file's author replaces it, and only the
// version they saw.
func (s *state) checkOwner(pathID, author string, replaces uint64) (*File, error) {
	cur := s.files[pathID]
	switch {
	case cur == nil && replaces != 0:
		return nil, errors.New("no such file")
	case cur == nil:
		return nil, nil
	case cur.Author != author:
		return nil, fmt.Errorf("file belongs to %q", cur.Author)
	case cur.Seq != replaces:
		return nil, fmt.Errorf("stale write: file is at entry %d, not %d", cur.Seq, replaces)
	}
	return cur, nil
}

// apply validates e against the current state and returns the mutation to
// commit, so an entry that fails to persist leaves the state untouched.
func (s *state) apply(e *Entry) (func(), error) {
	if commit, handled, err := s.applyConfig(e); handled {
		return commit, err
	}
	if commit, handled, err := s.m.apply(e); handled {
		return commit, err
	}
	decode := func(v any) error { return json.Unmarshal(e.Body, v) }
	switch e.Type {
	case TypeSegmentAdd:
		var b SegmentAdd
		if err := decode(&b); err != nil {
			return nil, err
		}
		if b.ID == "" || b.CipherSize <= 0 || b.ShardRoot == "" {
			return nil, errors.New("incomplete segment")
		}
		if cur := s.segments[b.ID]; cur != nil && cur.Live() {
			return nil, errors.New("segment already live")
		}
		return func() { s.segments[b.ID] = &Segment{SegmentAdd: b, RefsChangedMs: e.TimeMs} }, nil

	case TypeSegmentSource:
		var b SegmentSource
		if err := decode(&b); err != nil {
			return nil, err
		}
		seg, err := s.live(b.ID)
		if err != nil {
			return nil, err
		}
		// A claimed source can't displace one that works, so a member can't
		// detach a segment from its real torrent by racing in a fake one.
		if seg.Source != nil && seg.Swarm != SwarmDead {
			return nil, errors.New("segment already has a working source")
		}
		return func() { seg.Source, seg.Swarm = b.Source, SwarmUnknown }, nil

	case TypeSegmentSwarm:
		var b SegmentSwarm
		if err := decode(&b); err != nil {
			return nil, err
		}
		seg, err := s.live(b.ID)
		if err != nil {
			return nil, err
		}
		if seg.Source == nil {
			return nil, errors.New("segment has no source")
		}
		return func() {
			seg.Swarm = SwarmDead
			if b.Healthy {
				seg.Swarm = SwarmHealthy
			}
		}, nil

	case TypeSegmentGC:
		var b SegmentGC
		if err := decode(&b); err != nil {
			return nil, err
		}
		seg, err := s.live(b.ID)
		if err != nil {
			return nil, err
		}
		if seg.Refs != 0 {
			return nil, fmt.Errorf("segment still referenced by %d files", seg.Refs)
		}
		return func() { seg.GCAtMs, seg.Swarm = e.TimeMs, SwarmUnknown }, nil

	case TypeFilePut:
		var b FilePut
		if err := decode(&b); err != nil {
			return nil, err
		}
		if b.PathID == "" || len(b.Manifest) == 0 {
			return nil, errors.New("incomplete file")
		}
		if err := s.checkAuthor(b.Author, b.Message(), b.Sig); err != nil {
			return nil, err
		}
		old, err := s.checkOwner(b.PathID, b.Author, b.Replaces)
		if err != nil {
			return nil, err
		}
		for _, id := range b.Segments {
			if _, err := s.live(id); err != nil {
				return nil, err
			}
		}
		return func() {
			if old != nil {
				s.ref(old.Segments, -1, e.TimeMs)
			}
			s.ref(b.Segments, +1, e.TimeMs)
			s.files[b.PathID] = &File{FilePut: b, Seq: e.Seq}
		}, nil

	case TypeFileDel:
		var b FileDel
		if err := decode(&b); err != nil {
			return nil, err
		}
		if err := s.checkAuthor(b.Author, b.Message(), b.Sig); err != nil {
			return nil, err
		}
		old, err := s.checkOwner(b.PathID, b.Author, b.Replaces)
		if err != nil {
			return nil, err
		}
		if old == nil {
			return nil, errors.New("no such file")
		}
		return func() {
			s.ref(old.Segments, -1, e.TimeMs)
			delete(s.files, b.PathID)
		}, nil
	}
	return nil, fmt.Errorf("unknown entry type %q", e.Type)
}
