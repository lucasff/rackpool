// Package bridge connects pool segments to their original public torrent.
//
// A segment added from a known release carries a sealed SourceRef: the torrent
// infohash, file path and byte range it came from. Only pool members can open
// it, so the coordinator schedules bridge work without learning what the
// content is. Bridge nodes (opt-in operators who accept public-swarm exposure)
// use it to check swarm health and to rebuild segments from the swarm.
package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"mediapool/internal/codec"
)

type SourceRef struct {
	Infohash string `json:"infohash"`
	File     string `json:"file"`   // path inside the torrent
	Offset   int64  `json:"offset"` // plaintext offset of the segment in File
	Length   int64  `json:"length"`
}

// Source fetches plaintext byte ranges of torrent files.
type Source interface {
	ReadRange(ctx context.Context, ref SourceRef) ([]byte, error)
	Healthy(ctx context.Context, ref SourceRef) (bool, error)
}

const blobPurpose = "source-ref"

func SealRef(poolSecret []byte, ref SourceRef) ([]byte, error) {
	b, err := json.Marshal(ref)
	if err != nil {
		return nil, err
	}
	return codec.SealBlob(poolSecret, blobPurpose, b)
}

func OpenRef(poolSecret, blob []byte) (SourceRef, error) {
	var ref SourceRef
	b, err := codec.OpenBlob(poolSecret, blobPurpose, blob)
	if err != nil {
		return ref, err
	}
	return ref, json.Unmarshal(b, &ref)
}

// Mirror serves torrent files from a local directory laid out as
// <Dir>/<infohash>/<file>. It stands in for the public swarm in tests and
// local experiments; SetHealthy simulates a swarm dying.
type Mirror struct {
	Dir string

	mu   sync.Mutex
	dead map[string]bool
}

func (m *Mirror) SetHealthy(infohash string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dead == nil {
		m.dead = map[string]bool{}
	}
	m.dead[infohash] = !ok
}

func (m *Mirror) path(ref SourceRef) string {
	return filepath.Join(m.Dir, ref.Infohash, filepath.FromSlash(ref.File))
}

func (m *Mirror) Healthy(_ context.Context, ref SourceRef) (bool, error) {
	m.mu.Lock()
	dead := m.dead[ref.Infohash]
	m.mu.Unlock()
	if dead {
		return false, nil
	}
	_, err := os.Stat(m.path(ref))
	return err == nil, nil
}

func (m *Mirror) ReadRange(ctx context.Context, ref SourceRef) ([]byte, error) {
	if ok, _ := m.Healthy(ctx, ref); !ok {
		return nil, fmt.Errorf("bridge: swarm for %s unavailable", ref.Infohash)
	}
	f, err := os.Open(m.path(ref))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, ref.Length)
	if _, err := f.ReadAt(buf, ref.Offset); err != nil {
		return nil, fmt.Errorf("bridge: read %s@%d: %w", ref.File, ref.Offset, err)
	}
	return buf, nil
}
