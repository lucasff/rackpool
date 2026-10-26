// Package limits holds the operator-facing resource controls: human-readable
// size and rate flags, and a token-bucket throttle for node traffic.
package limits

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bytes is a size flag: "500G", "1.5T", "64M", "0" (decimal units: G = 1e9,
// matching how disks are sold; "GiB"/"Gi" for binary).
type Bytes int64

func (b *Bytes) String() string { return FormatBytes(int64(*b)) }

func (b *Bytes) Set(s string) error {
	n, err := parseUnits(s, "B")
	*b = Bytes(n)
	return err
}

// Rate is a bandwidth flag in bits per second, the way connections are
// sold: "50M" or "50Mbit" is 50 megabits/s; "0" is unlimited. BytesPerSec
// converts it for the throttle.
type Rate int64

func (r *Rate) String() string {
	if *r == 0 {
		return "unlimited"
	}
	return FormatBytes(int64(*r)) + "bit/s"
}

func (r *Rate) Set(s string) error {
	s = strings.TrimSpace(s)
	for _, suf := range []string{"/s", "ps", "bit", "b"} {
		s = strings.TrimSuffix(s, suf)
	}
	n, err := parseUnits(s, "")
	*r = Rate(n)
	return err
}

func (r Rate) BytesPerSec() int64 { return int64(r) / 8 }

func parseUnits(s, unitSuffix string) (int64, error) {
	s = strings.TrimSpace(s)
	if unitSuffix != "" {
		s = strings.TrimSuffix(s, unitSuffix)
	}
	mult := 1.0
	for _, u := range []struct {
		suffix string
		mult   float64
	}{
		{"Ti", 1 << 40}, {"Gi", 1 << 30}, {"Mi", 1 << 20}, {"Ki", 1 << 10},
		{"T", 1e12}, {"G", 1e9}, {"M", 1e6}, {"K", 1e3}, {"k", 1e3},
	} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid size %q (examples: 500G, 1.5T, 64Mi, 0)", s)
	}
	return int64(f * mult), nil
}

func FormatBytes(n int64) string {
	switch {
	case n == 0:
		return "0"
	case n >= 1e12:
		return strconv.FormatFloat(float64(n)/1e12, 'g', 4, 64) + "T"
	case n >= 1e9:
		return strconv.FormatFloat(float64(n)/1e9, 'g', 4, 64) + "G"
	case n >= 1e6:
		return strconv.FormatFloat(float64(n)/1e6, 'g', 4, 64) + "M"
	case n >= 1e3:
		return strconv.FormatFloat(float64(n)/1e3, 'g', 4, 64) + "K"
	}
	return strconv.FormatInt(n, 10)
}

// Bucket is a token-bucket throttle shared by every transfer in one
// direction. A nil *Bucket, or a zero rate, means unlimited. The rate can be
// changed while running.
type Bucket struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	tokens float64
	last   time.Time
}

func NewBucket(bytesPerSec int64) *Bucket {
	return &Bucket{rate: float64(bytesPerSec), last: time.Now()}
}

func (b *Bucket) SetRate(bytesPerSec int64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.rate = float64(bytesPerSec)
	b.mu.Unlock()
}

// burst bounds how much unused allowance can be saved up: a quarter second
// of traffic, so a long idle spell doesn't permit a huge spike.
func (b *Bucket) burst() float64 { return max(b.rate/4, 64<<10) }

// Wait blocks until n bytes may be sent, or ctx is done.
func (b *Bucket) Wait(ctx context.Context, n int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.rate <= 0 {
		b.mu.Unlock()
		return nil
	}
	now := time.Now()
	b.tokens = min(b.tokens+now.Sub(b.last).Seconds()*b.rate, b.burst())
	b.last = now
	b.tokens -= float64(n) // may go negative: the debt is the wait
	wait := time.Duration(-b.tokens / b.rate * float64(time.Second))
	b.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

const chunk = 32 << 10

// Writer throttles writes to w.
type Writer struct {
	Ctx context.Context
	W   io.Writer
	B   *Bucket
}

func (t Writer) Write(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c := min(chunk, len(p)-n)
		if err := t.B.Wait(t.Ctx, c); err != nil {
			return n, err
		}
		m, err := t.W.Write(p[n : n+c])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

type reader struct {
	ctx context.Context
	r   io.ReadCloser
	b   *Bucket
}

func (t *reader) Read(p []byte) (int, error) {
	if len(p) > chunk {
		p = p[:chunk]
	}
	n, err := t.r.Read(p)
	if n > 0 {
		if werr := t.b.Wait(t.ctx, n); werr != nil {
			return n, werr
		}
	}
	return n, err
}

func (t *reader) Close() error { return t.r.Close() }

// Transport throttles request bodies against Up and response bodies against
// Down, so every outgoing transfer a node makes shares its caps.
type Transport struct {
	Base     http.RoundTripper
	Up, Down *Bucket
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Body != nil && t.Up != nil {
		req = req.Clone(req.Context())
		req.Body = &reader{ctx: req.Context(), r: req.Body, b: t.Up}
	}
	resp, err := base.RoundTrip(req)
	if err == nil && t.Down != nil {
		resp.Body = &reader{ctx: req.Context(), r: resp.Body, b: t.Down}
	}
	return resp, err
}
