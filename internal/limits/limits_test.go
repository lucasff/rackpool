package limits

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]int64{"500G": 500e9, "1.5T": 1.5e12, "64Mi": 64 << 20, "0": 0, "123": 123, "10MB": 10e6} {
		var b Bytes
		if err := b.Set(in); err != nil || int64(b) != want {
			t.Errorf("Bytes(%q) = %d, %v; want %d", in, b, err, want)
		}
	}
	for in, want := range map[string]int64{"50M": 50e6, "50Mbit": 50e6, "1Gbps": 1e9, "100Mbit/s": 100e6} {
		var r Rate
		if err := r.Set(in); err != nil || int64(r) != want {
			t.Errorf("Rate(%q) = %d, %v; want %d", in, r, err, want)
		}
	}
	var b Bytes
	if b.Set("lots") == nil || b.Set("-5G") == nil {
		t.Error("garbage sizes accepted")
	}
}

func TestBucketThrottles(t *testing.T) {
	b := NewBucket(2 << 20) // 2 MiB/s
	var dst bytes.Buffer
	start := time.Now()
	if _, err := io.Copy(Writer{Ctx: context.Background(), W: &dst, B: b}, bytes.NewReader(make([]byte, 1<<20))); err != nil {
		t.Fatal(err)
	}
	// 1 MiB at 2 MiB/s, minus the small initial burst allowance.
	if d := time.Since(start); d < 350*time.Millisecond || d > 900*time.Millisecond {
		t.Fatalf("1 MiB at 2 MiB/s took %v", d)
	}

	var unlimited *Bucket
	start = time.Now()
	io.Copy(Writer{Ctx: context.Background(), W: io.Discard, B: unlimited}, bytes.NewReader(make([]byte, 8<<20)))
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("nil bucket throttled: %v", d)
	}
}
