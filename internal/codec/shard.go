package codec

import (
	"encoding/hex"
	"fmt"
	"strings"

	"mediapool/internal/merkle"
)

// Each shard is hashed as a Merkle tree over ChunkSize chunks, so a storage
// proof costs one chunk plus log2 hashes instead of the whole shard. A
// segment's shard hashes form a second tree whose root is the only thing the
// catalog stores per segment.
//
// Chunks are also the unit of range reads, so they're kept small: over a
// 10 Mbit/s home uplink a 256 KiB chunk arrives in about 0.2 s.
const ChunkSize = 256 << 10

// ShardSize is the length of every shard of a segment.
func ShardSize(p Params, cipherSize int) int { return NewLayout(p.K, cipherSize).ShardSize() }

// Layout maps a segment's ciphertext onto its K data shards, striped like
// RAID-0: ciphertext chunk n goes to data shard n mod K, as that shard's
// chunk n/K. Any contiguous range is then spread across holders, so a seek
// or a player filling its buffer reads from several nodes at once instead
// of one. Every shard chunk is one contiguous ciphertext range, which is
// what lets a reader verify and decrypt chunks on their own.
//
// The last, partial stripe is split evenly (Tail bytes per shard) rather
// than padded to a whole stripe, so a segment wastes at most K-1 bytes.
type Layout struct {
	K, Len int
	Full   int // complete stripes of K*ChunkSize bytes
	Tail   int // bytes per shard in the final partial stripe
}

func NewLayout(k, ctLen int) Layout {
	full := ctLen / (k * ChunkSize)
	rest := ctLen - full*k*ChunkSize
	return Layout{K: k, Len: ctLen, Full: full, Tail: (rest + k - 1) / k}
}

func (l Layout) ShardSize() int { return max(1, l.Full*ChunkSize+l.Tail) }

// Chunks is the number of chunks per data shard.
func (l Layout) Chunks() int { return NumChunks(l.ShardSize()) }

// Span is the ciphertext range [start, end) held by chunk cc of data shard
// d. It may run past Len (padding), which callers clip.
func (l Layout) Span(d, cc int) (start, end int) {
	if cc < l.Full {
		start = cc*l.K*ChunkSize + d*ChunkSize
		return start, start + ChunkSize
	}
	start = l.Full*l.K*ChunkSize + d*l.Tail
	return start, start + l.Tail
}

// Locate returns the data shard and chunk holding ciphertext offset x.
func (l Layout) Locate(x int) (d, cc int) {
	if x < l.Full*l.K*ChunkSize {
		return (x / ChunkSize) % l.K, x / (l.K * ChunkSize)
	}
	return min((x-l.Full*l.K*ChunkSize)/max(l.Tail, 1), l.K-1), l.Full
}

func NumChunks(shardSize int) int { return max(1, (shardSize+ChunkSize-1)/ChunkSize) }

func chunkLeaves(data []byte) []merkle.Hash {
	n := NumChunks(len(data))
	out := make([]merkle.Hash, n)
	for i := range n {
		out[i] = merkle.Leaf(data[i*ChunkSize : min((i+1)*ChunkSize, len(data))])
	}
	return out
}

func ShardHash(data []byte) merkle.Hash { return merkle.Root(chunkLeaves(data)) }

// ChunkProof returns chunk i of a shard and its proof against ShardHash.
func ChunkProof(data []byte, i int) ([]byte, []merkle.Hash, error) {
	if i < 0 || i >= NumChunks(len(data)) {
		return nil, nil, fmt.Errorf("codec: chunk %d out of range", i)
	}
	return data[i*ChunkSize : min((i+1)*ChunkSize, len(data))], merkle.Proof(chunkLeaves(data), i), nil
}

// VerifyChunk checks chunk i of a shard of the given size. The verifier
// supplies shardSize, so a holder can't pass a proof for a truncated shard.
func VerifyChunk(shardHash merkle.Hash, shardSize, i int, chunk []byte, proof []merkle.Hash) bool {
	n := NumChunks(shardSize)
	if i < 0 || i >= n || len(chunk) != min(ChunkSize, shardSize-i*ChunkSize) {
		return false
	}
	return merkle.Verify(merkle.Leaf(chunk), i, n, proof, shardHash)
}

// Tree is the Merkle tree over a segment's full set of MaxN shard hashes.
type Tree struct {
	Hashes []merkle.Hash
	Root   merkle.Hash
	leaves []merkle.Hash
}

func NewTree(shards [][]byte) Tree {
	t := Tree{Hashes: make([]merkle.Hash, len(shards)), leaves: make([]merkle.Hash, len(shards))}
	for i, s := range shards {
		t.Hashes[i] = ShardHash(s)
		t.leaves[i] = merkle.Leaf(t.Hashes[i][:])
	}
	t.Root = merkle.Root(t.leaves)
	return t
}

func (t Tree) Proof(i int) []merkle.Hash { return merkle.Proof(t.leaves, i) }

func VerifyShardHash(root merkle.Hash, maxN, idx int, shardHash merkle.Hash, proof []merkle.Hash) bool {
	return merkle.Verify(merkle.Leaf(shardHash[:]), idx, maxN, proof, root)
}

// VerifyShard checks that data is shard idx of the segment with this root.
func VerifyShard(root merkle.Hash, maxN, idx int, data []byte, proof []merkle.Hash) bool {
	return VerifyShardHash(root, maxN, idx, ShardHash(data), proof)
}

func HashToHex(h merkle.Hash) string { return hex.EncodeToString(h[:]) }

func HexToHash(s string) (merkle.Hash, error) {
	var h merkle.Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, fmt.Errorf("codec: bad hash %q", s)
	}
	copy(h[:], b)
	return h, nil
}

// EncodeProof renders a proof as comma-separated hex, for HTTP headers.
func EncodeProof(p []merkle.Hash) string {
	parts := make([]string, len(p))
	for i, h := range p {
		parts[i] = HashToHex(h)
	}
	return strings.Join(parts, ",")
}

func DecodeProof(s string) ([]merkle.Hash, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > 64 {
		return nil, fmt.Errorf("codec: proof too long")
	}
	out := make([]merkle.Hash, len(parts))
	for i, p := range parts {
		h, err := HexToHash(p)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}
