// Package codec turns plaintext segments into encrypted, erasure-coded shards.
//
// Encryption is convergent within a pool: the key is derived from the segment's
// plaintext and the pool secret, so two members adding the same bytes produce
// the same ciphertext (and the pool stores it once), while anyone outside the
// pool cannot confirm what the pool holds.
package codec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

// Params fixes the erasure code for a pool. Every segment is encoded to MaxN
// shards so that any shard index can be regenerated later from any K others;
// the durability class and heat only decide how many indices are placed.
type Params struct {
	K    int `json:"k"`
	MaxN int `json:"max_n"`
}

func (p Params) Validate() error {
	if p.K < 1 || p.MaxN <= p.K || p.MaxN > 256 {
		return fmt.Errorf("codec: invalid params k=%d max_n=%d", p.K, p.MaxN)
	}
	return nil
}

// HashHex returns the hex SHA-256 of b. Segment IDs are HashHex(ciphertext).
func HashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func derive(poolSecret []byte, purpose string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, poolSecret)
	m.Write([]byte("mediapool/" + purpose + "/v1"))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// ConvergentKey derives a segment's encryption key from its plaintext.
func ConvergentKey(poolSecret, plain []byte) []byte {
	h := sha256.Sum256(plain)
	return derive(poolSecret, "segment-key", h[:])
}

// KeyedID derives a stable identifier that only pool members can compute.
func KeyedID(poolSecret []byte, purpose string, data []byte) string {
	return hex.EncodeToString(derive(poolSecret, "id/"+purpose, data))
}

var zeroNonce = make([]byte, 12)

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealSegment encrypts a segment with its convergent key and returns the key,
// the ciphertext and the segment ID.
//
// It uses AES-256-GCM with an all-zero nonce. That is safe only because each
// key encrypts exactly one plaintext (the key is derived from it), and it is
// what makes identical segments produce identical ciphertext.
func SealSegment(poolSecret, plain []byte) (key, ct []byte, id string, err error) {
	key = ConvergentKey(poolSecret, plain)
	aead, err := gcm(key)
	if err != nil {
		return nil, nil, "", err
	}
	ct = aead.Seal(nil, zeroNonce, plain, nil)
	return key, ct, HashHex(ct), nil
}

// OpenSegment decrypts a segment sealed by SealSegment.
func OpenSegment(key, ct []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, zeroNonce, ct, nil)
}

// SealBlob encrypts small pool-private records (manifests, torrent source
// references) with a random nonce, so they can sit on the coordinator unread.
func SealBlob(poolSecret []byte, purpose string, plain []byte) ([]byte, error) {
	aead, err := gcm(derive(poolSecret, "blob/"+purpose))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(purpose)), nil
}

func OpenBlob(poolSecret []byte, purpose string, blob []byte) ([]byte, error) {
	aead, err := gcm(derive(poolSecret, "blob/"+purpose))
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, errors.New("codec: blob too short")
	}
	n := aead.NonceSize()
	return aead.Open(nil, blob[:n], blob[n:], []byte(purpose))
}

// Encode splits ciphertext into p.MaxN shards: K data shards plus MaxN-K parity.
func Encode(p Params, ct []byte) ([][]byte, error) {
	enc, err := reedsolomon.New(p.K, p.MaxN-p.K)
	if err != nil {
		return nil, err
	}
	// Split may reuse spare capacity of its input, so hand it a private copy.
	shards, err := enc.Split(bytes.Clone(ct))
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

// Reconstruct fills every nil entry of shards (len p.MaxN) from any K present.
func Reconstruct(p Params, shards [][]byte) error {
	enc, err := reedsolomon.New(p.K, p.MaxN-p.K)
	if err != nil {
		return err
	}
	return enc.Reconstruct(shards)
}

// Join reassembles the ciphertext of the given size from a full shard set.
func Join(p Params, shards [][]byte, size int) ([]byte, error) {
	enc, err := reedsolomon.New(p.K, p.MaxN-p.K)
	if err != nil {
		return nil, err
	}
	if err := enc.ReconstructData(shards); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := enc.Join(&buf, shards, size); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
