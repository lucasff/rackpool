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
