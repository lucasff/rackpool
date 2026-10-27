package codec

import (
	"bytes"
	"testing"
)

func TestConvergentDedupIsPoolScoped(t *testing.T) {
	plain := []byte("same bytes from two members")
	_, ct1, id1, _ := SealSegment([]byte("pool-a"), plain)
	_, ct2, id2, _ := SealSegment([]byte("pool-a"), plain)
	_, _, id3, _ := SealSegment([]byte("pool-b"), plain)
	if id1 != id2 || !bytes.Equal(ct1, ct2) {
		t.Fatal("same pool, same plaintext must give identical ciphertext")
	}
	if id1 == id3 {
		t.Fatal("another pool's secret must not reproduce the segment id (confirmation attack)")
	}
}

func TestEncodeReconstructAnyK(t *testing.T) {
	p := Params{K: 4, MaxN: 12}
	key, ct, _, _ := SealSegment([]byte("s"), bytes.Repeat([]byte("media"), 9999))
	shards, err := Encode(p, ct)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]string, len(shards))
	for i, s := range shards {
		want[i] = HashHex(s)
	}

	// Keep only parity shards 7, 8, 10, 11: regenerate everything else.
	partial := make([][]byte, p.MaxN)
	for _, i := range []int{7, 8, 10, 11} {
		partial[i] = shards[i]
	}
	if err := Reconstruct(p, partial); err != nil {
		t.Fatal(err)
	}
	for i, s := range partial {
		if HashHex(s) != want[i] {
			t.Fatalf("regenerated shard %d differs", i)
		}
	}
	joined, err := Join(p, partial, len(ct))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSegment(key, joined); err != nil {
		t.Fatal(err)
	}
}

func TestBlobNeedsSecretAndPurpose(t *testing.T) {
	blob, _ := SealBlob([]byte("s"), "manifest", []byte("/movies/x.mkv"))
	if _, err := OpenBlob([]byte("other"), "manifest", blob); err == nil {
		t.Fatal("opened with wrong secret")
	}
	if _, err := OpenBlob([]byte("s"), "source-ref", blob); err == nil {
		t.Fatal("opened under wrong purpose")
	}
}

func TestDecryptRangeMatchesGCM(t *testing.T) {
	plain := make([]byte, 100000)
	for i := range plain {
		plain[i] = byte(i*7 + i/300)
	}
	key, ct, _, _ := SealSegment([]byte("s"), plain)
	for _, r := range [][2]int{{0, 1}, {0, 16}, {5, 40}, {15, 17}, {4096, 70001}, {99990, 100000}, {0, 100000}} {
		got, err := DecryptRange(key, ct[r[0]:r[1]], int64(r[0]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain[r[0]:r[1]]) {
			t.Fatalf("range %v decrypts wrong", r)
		}
	}
}

func TestStripedLayoutRoundTrips(t *testing.T) {
	for _, k := range []int{1, 4, 10} {
		for _, n := range []int{1, 7, ChunkSize - 1, ChunkSize * k, ChunkSize*k + 5, 3*ChunkSize*k + ChunkSize/2 + 11} {
			p := Params{K: k, MaxN: k + 3}
			ct := make([]byte, n)
			for i := range ct {
				ct[i] = byte(i*31 + i>>9)
			}
			lay := NewLayout(k, n)
			seen := make([]int, n)
			for d := range k {
				for cc := range lay.Chunks() {
					s, e := lay.Span(d, cc)
					for x := s; x < min(e, n); x++ {
						seen[x]++
						if gd, gc := lay.Locate(x); gd != d || gc != cc {
							t.Fatalf("k=%d n=%d: Locate(%d)=(%d,%d), want (%d,%d)", k, n, x, gd, gc, d, cc)
						}
					}
				}
			}
			for x, c := range seen {
				if c != 1 {
					t.Fatalf("k=%d n=%d: byte %d covered %d times", k, n, x, c)
				}
			}
			shards, err := Encode(p, ct)
			if err != nil {
				t.Fatal(err)
			}
			shards[0], shards[k-1] = nil, nil // lose data shards
			if k == 1 {
				shards[k-1] = nil
			}
			got, err := Join(p, shards, n)
			if err != nil || !bytes.Equal(got, ct) {
				t.Fatalf("k=%d n=%d: join failed: %v", k, n, err)
			}
		}
	}
}
