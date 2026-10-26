package mediapooltest

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"mediapool/pkg/mediapool"
)

func TestPoolRoundTrip(t *testing.T) {
	p := Start(t, 12)
	ctx := context.Background()
	alice, err := mediapool.Open(p.Config("alice"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	data := bytes.Repeat([]byte("mediapool"), 1000)
	mt := time.Unix(1700000000, 123456789)
	e, err := alice.Put(ctx, "/a/b.txt", bytes.NewReader(data), mt)
	if err != nil {
		t.Fatal(err)
	}
	if e.Size != int64(len(data)) || !e.ModTime.Equal(mt) || e.Author != "alice" {
		t.Fatalf("entry %+v", e)
	}
	bob, err := mediapool.Open(p.Config("bob"))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	r, err := bob.Open(ctx, "/a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back: %v", err)
	}
	if err := bob.Remove(ctx, "/a/b.txt"); err == nil {
		t.Fatal("bob removed alice's file")
	}
}
