// Package merkle implements RFC 9162 Merkle trees: leaf and interior hashes
// are domain-separated, and a tree of any size is split at the largest power
// of two, so an inclusion proof is at most log2(n) hashes.
package merkle

import "crypto/sha256"

type Hash = [32]byte

// Leaf hashes raw data as a tree leaf.
func Leaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

func interior(l, r Hash) Hash {
	var buf [65]byte
	buf[0] = 1
	copy(buf[1:], l[:])
	copy(buf[33:], r[:])
	return sha256.Sum256(buf[:])
}

// split returns the largest power of two smaller than n (n >= 2).
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root returns the tree hash over already-hashed leaves. It panics on an
// empty slice.
func Root(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		panic("merkle: empty tree")
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return interior(Root(leaves[:k]), Root(leaves[k:]))
}

// Proof returns the inclusion proof for leaf i, ordered bottom-up.
func Proof(leaves []Hash, i int) []Hash {
	if len(leaves) <= 1 {
		return nil
	}
	k := split(len(leaves))
	if i < k {
		return append(Proof(leaves[:k], i), Root(leaves[k:]))
	}
	return append(Proof(leaves[k:], i-k), Root(leaves[:k]))
}

// Verify checks that leaf is entry i of an n-leaf tree with the given root
// (RFC 9162 section 2.1.3.2).
func Verify(leaf Hash, i, n int, proof []Hash, root Hash) bool {
	if i < 0 || i >= n {
		return false
	}
	fn, sn, r := i, n-1, leaf
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = interior(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = interior(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}
