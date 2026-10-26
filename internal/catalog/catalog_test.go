package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var (
	pub, writer, _         = ed25519.GenerateKey(rand.Reader)
	_, forgerKey, _        = ed25519.GenerateKey(rand.Reader)
	alicePub, alice, _     = ed25519.GenerateKey(rand.Reader)
	malloryPub, mallory, _ = ed25519.GenerateKey(rand.Reader)
)

func members(name string) ed25519.PublicKey {
	switch name {
	case "alice":
		return alicePub
	case "mallory":
		return malloryPub
	}
	return nil
}

func open(t *testing.T, path string) *Catalog {
	t.Helper()
	c, err := Open(path, pub, members)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func seg(id string) SegmentAdd { return SegmentAdd{ID: id, CipherSize: 10, ShardRoot: "r"} }

func put(key ed25519.PrivateKey, author, path string, replaces uint64, segs ...string) FilePut {
	b := FilePut{PathID: path, Author: author, Replaces: replaces, Segments: segs, Manifest: []byte("m")}
	b.Sig = ed25519.Sign(key, b.Message())
	return b
}

func del(key ed25519.PrivateKey, author, path string, replaces uint64) FileDel {
	b := FileDel{PathID: path, Author: author, Replaces: replaces}
	b.Sig = ed25519.Sign(key, b.Message())
	return b
}

func mustAppend(t *testing.T, c *Catalog, typ string, body any) Entry {
	t.Helper()
	e, err := c.Append(writer, typ, body)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestReopenReplaysAndDropsTornWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	c := open(t, path)
	mustAppend(t, c, TypeSegmentAdd, seg("s1"))
	e := mustAppend(t, c, TypeFilePut, put(alice, "alice", "p", 0, "s1"))
	head := c.Head()
	c.Close()

	// A crash halfway through writing a third entry.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"seq":3,"prev":"ab`)
	f.Close()

	c = open(t, path)
	if c.Head() != head {
		t.Fatalf("head %+v after reopen, want %+v", c.Head(), head)
	}
	if s, _ := c.Segment("s1"); s.Refs != 1 {
		t.Fatalf("refs not replayed: %+v", s)
	}
	mustAppend(t, c, TypeFileDel, del(alice, "alice", "p", e.Seq)) // log is appendable again
}

func TestReplicaRejectsForgeriesAndForks(t *testing.T) {
	src := open(t, "")
	mustAppend(t, src, TypeSegmentAdd, seg("s1"))
	mustAppend(t, src, TypeSegmentAdd, seg("s2"))
	entries := src.Entries(1, 10)

	replica := open(t, "")
	if n, err := replica.Ingest(entries); err != nil || n != 2 {
		t.Fatalf("ingest: n=%d err=%v", n, err)
	}
	if n, err := replica.Ingest(entries); err != nil || n != 0 {
		t.Fatalf("re-ingesting known entries must be a no-op: n=%d err=%v", n, err)
	}

	// A member who knows the pool secret but not the coordinator key.
	forger := open(t, "")
	if _, err := forger.Append(forgerKey, TypeSegmentAdd, seg("x")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged signature: %v", err)
	}

	// A tampered body.
	tampered := entries[0]
	tampered.Body = []byte(`{"id":"evil","cipher_size":10,"shard_root":"r"}`)
	if _, err := open(t, "").Ingest([]Entry{tampered}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered body: %v", err)
	}

	// A different history signed by the same key: a fork.
	other := open(t, "")
	mustAppend(t, other, TypeSegmentAdd, seg("s9"))
	mustAppend(t, other, TypeSegmentAdd, seg("s8"))
	mustAppend(t, other, TypeSegmentAdd, seg("s7"))
	if _, err := replica.Ingest(other.Entries(1, 10)); !errors.Is(err, ErrFork) {
		t.Fatalf("fork: %v", err)
	}
	if _, err := replica.Ingest(other.Entries(3, 10)); !errors.Is(err, ErrFork) {
		t.Fatalf("fork past head: %v", err)
	}
}

func TestReferenceCountingAndGC(t *testing.T) {
	c := open(t, "")
	mustAppend(t, c, TypeSegmentAdd, seg("s1"))
	mustAppend(t, c, TypeSegmentAdd, seg("s2"))
	a := mustAppend(t, c, TypeFilePut, put(alice, "alice", "a", 0, "s1", "s2"))
	mustAppend(t, c, TypeFilePut, put(alice, "alice", "b", 0, "s1"))

	if _, err := c.Append(writer, TypeSegmentGC, SegmentGC{ID: "s1"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("collected a referenced segment: %v", err)
	}
	mustAppend(t, c, TypeFileDel, del(alice, "alice", "a", a.Seq))
	if s, _ := c.Segment("s1"); s.Refs != 1 {
		t.Fatalf("s1 refs %d, want 1", s.Refs)
	}
	mustAppend(t, c, TypeSegmentGC, SegmentGC{ID: "s2"})
	if s, _ := c.Segment("s2"); s.Live() {
		t.Fatal("s2 should be tombstoned")
	}
	if _, err := c.Append(writer, TypeFilePut, put(alice, "alice", "c", 0, "s2")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("file referencing a collected segment: %v", err)
	}
	mustAppend(t, c, TypeSegmentAdd, seg("s2")) // re-adding revives it
	if s, _ := c.Segment("s2"); !s.Live() || s.Refs != 0 {
		t.Fatalf("revived s2: %+v", s)
	}
}

// The coordinator signs the log, but file changes also carry the author's
// signature: a compromised coordinator or another member can't delete or
// overwrite someone's files, which is what keeps their segments from GC.
func TestFileChangesNeedTheAuthor(t *testing.T) {
	c := open(t, "")
	mustAppend(t, c, TypeSegmentAdd, seg("s1"))
	a := mustAppend(t, c, TypeFilePut, put(alice, "alice", "a", 0, "s1"))

	cases := map[string]any{
		"overwrite by another member":             put(mallory, "mallory", "a", a.Seq, "s1"),
		"delete by another member":                del(mallory, "mallory", "a", a.Seq),
		"delete signed by the wrong key":          del(mallory, "alice", "a", a.Seq),
		"create claiming a new path is a replace": put(alice, "alice", "a", 0, "s1"),
		"non-member author":                       put(mallory, "eve", "z", 0, "s1"),
	}
	for name, body := range cases {
		typ := TypeFilePut
		if _, ok := body.(FileDel); ok {
			typ = TypeFileDel
		}
		if _, err := c.Append(writer, typ, body); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}

	d := mustAppend(t, c, TypeFileDel, del(alice, "alice", "a", a.Seq))
	// Replaying the old put after the delete doesn't resurrect anything.
	if _, err := c.Append(writer, TypeFilePut, put(alice, "alice", "a", a.Seq, "s1")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replayed put after delete: %v (delete at %d)", err, d.Seq)
	}
}
