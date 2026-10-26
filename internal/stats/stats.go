// Package stats counts transfers for `mp` commands and the rc core/stats
// call.
package stats

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	mu        sync.Mutex
	start     time.Time
	bytes     atomic.Int64
	transfers int64
	errors    int64
	lastError string
	active    map[*Transfer]bool
}

func New() *Stats { return &Stats{start: time.Now(), active: map[*Transfer]bool{}} }

type Transfer struct {
	s     *Stats
	Name  string
	Size  int64
	bytes atomic.Int64
	Start time.Time
}

// Begin registers a transfer; call Done when it finishes.
func (s *Stats) Begin(name string, size int64) *Transfer {
	t := &Transfer{s: s, Name: name, Size: size, Start: time.Now()}
	s.mu.Lock()
	s.active[t] = true
	s.mu.Unlock()
	return t
}

func (t *Transfer) Add(n int64) {
	t.bytes.Add(n)
	t.s.bytes.Add(n)
}

func (t *Transfer) Done(err error) {
	s := t.s
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, t)
	if err != nil {
		s.errors++
		s.lastError = t.Name + ": " + err.Error()
	} else {
		s.transfers++
	}
}

// Reader counts bytes read through r against t.
func (t *Transfer) Reader(r io.Reader) io.Reader { return &counter{r: r, t: t} }

type counter struct {
	r io.Reader
	t *Transfer
}

func (c *counter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.t.Add(int64(n))
	return n, err
}

type Snapshot struct {
	Bytes        int64      `json:"bytes"`
	Speed        float64    `json:"speed"` // bytes/s since start or reset
	Transfers    int64      `json:"transfers"`
	Errors       int64      `json:"errors"`
	LastError    string     `json:"lastError,omitempty"`
	ElapsedTime  float64    `json:"elapsedTime"`
	Transferring []Progress `json:"transferring"`
}

type Progress struct {
	Name       string  `json:"name"`
	Size       int64   `json:"size"`
	Bytes      int64   `json:"bytes"`
	Percentage int     `json:"percentage"`
	Speed      float64 `json:"speed"`
}

func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	el := time.Since(s.start).Seconds()
	snap := Snapshot{Bytes: s.bytes.Load(), Transfers: s.transfers, Errors: s.errors, LastError: s.lastError, ElapsedTime: el, Transferring: []Progress{}}
	if el > 0 {
		snap.Speed = float64(snap.Bytes) / el
	}
	for t := range s.active {
		p := Progress{Name: t.Name, Size: t.Size, Bytes: t.bytes.Load()}
		if t.Size > 0 {
			p.Percentage = int(100 * p.Bytes / t.Size)
		}
		if d := time.Since(t.Start).Seconds(); d > 0 {
			p.Speed = float64(p.Bytes) / d
		}
		snap.Transferring = append(snap.Transferring, p)
	}
	return snap
}

func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.start, s.transfers, s.errors, s.lastError = time.Now(), 0, 0, ""
	s.bytes.Store(0)
}
