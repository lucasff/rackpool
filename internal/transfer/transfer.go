// Package transfer moves shards between nodes and clients, and carries
// signed JSON requests to the coordinator.
package transfer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"mediapool/internal/codec"
	"mediapool/internal/merkle"
	"mediapool/internal/proto"
)

const (
	ProofHeader      = "X-Shard-Proof"
	TicketHeader     = "X-Upload-Ticket"
	ShardHashHeader  = "X-Shard-Hash"
	ChunkProofHeader = "X-Chunk-Proof"
)

// MaxChunkRun is the most chunks one GetChunks request may ask for.
const MaxChunkRun = 64

// GetChunks fetches chunks [from, to) of shard idx in one request and
// calls got for each as soon as it has arrived and verified, in order. It
// returns the number of chunks delivered; on error the caller can retry
// the rest elsewhere.
//
// pace, if non-nil, runs before each chunk is read; blocking in it applies
// TCP backpressure, freeing the holder's upload for other requests.
func GetChunks(ctx context.Context, hc *http.Client, s Signer, addr, seg string, idx int, root merkle.Hash, maxN, shardSize, from, to int, pace func(), got func(c int, data []byte)) (int, error) {
	u := fmt.Sprintf("%s/v1/chunks/%s/%d?root=%s&from=%d&to=%d", addr, seg, idx, codec.HashToHex(root), from, to)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	if s != nil {
		s.Sign(req, nil)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, &HTTPError{resp.StatusCode, fmt.Sprintf("get chunks %.12s/%d/%d-%d from %s: %s", seg, idx, from, to, addr, resp.Status)}
	}
	shardHash, err := codec.HexToHash(resp.Header.Get(ShardHashHeader))
	if err != nil {
		return 0, err
	}
	segProof, err := codec.DecodeProof(resp.Header.Get(ProofHeader))
	if err != nil || !codec.VerifyShardHash(root, maxN, idx, shardHash, segProof) {
		return 0, fmt.Errorf("shard %.12s/%d from %s isn't part of the segment", seg, idx, addr)
	}
	proofs := strings.Split(resp.Header.Get(ChunkProofHeader), ";")
	n := 0
	for c := from; c < to && c < from+len(proofs); c++ {
		size := min(codec.ChunkSize, shardSize-c*codec.ChunkSize)
		if size <= 0 {
			break
		}
		if pace != nil {
			pace()
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(resp.Body, data); err != nil {
			return n, err
		}
		cp, err := codec.DecodeProof(proofs[c-from])
		if err != nil || !codec.VerifyChunk(shardHash, shardSize, c, data, cp) {
			return n, fmt.Errorf("chunk %.12s/%d/%d from %s doesn't verify", seg, idx, c, addr)
		}
		got(c, data)
		n++
	}
	return n, nil
}

// GetChunk fetches chunk c of shard idx and verifies it against the segment
// root: the shard hash must be in the segment tree and the chunk in the
// shard's tree. shardSize is computed by the caller from the catalog.
func GetChunk(ctx context.Context, hc *http.Client, s Signer, addr, seg string, idx int, root merkle.Hash, maxN, shardSize, c int) ([]byte, error) {
	u := fmt.Sprintf("%s/v1/chunk/%s/%d?root=%s&chunk=%d", addr, seg, idx, codec.HashToHex(root), c)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if s != nil {
		s.Sign(req, nil)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{resp.StatusCode, fmt.Sprintf("get chunk %.12s/%d/%d from %s: %s", seg, idx, c, addr, resp.Status)}
	}
	shardHash, err := codec.HexToHash(resp.Header.Get(ShardHashHeader))
	if err != nil {
		return nil, err
	}
	segProof, err1 := codec.DecodeProof(resp.Header.Get(ProofHeader))
	chunkProof, err2 := codec.DecodeProof(resp.Header.Get(ChunkProofHeader))
	if err1 != nil || err2 != nil {
		return nil, errors.New("malformed chunk proof")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, codec.ChunkSize+1))
	if err != nil {
		return nil, err
	}
	if !codec.VerifyShardHash(root, maxN, idx, shardHash, segProof) || !codec.VerifyChunk(shardHash, shardSize, c, data, chunkProof) {
		return nil, fmt.Errorf("chunk %.12s/%d/%d from %s doesn't verify", seg, idx, c, addr)
	}
	return data, nil
}

// Signer authenticates an outgoing request (auth.Identity implements it).
type Signer interface {
	Sign(req *http.Request, body []byte)
}

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status int
	Msg    string
}

func (e *HTTPError) Error() string { return e.Msg }

func shardURL(addr, seg string, idx int) string {
	return fmt.Sprintf("%s/v1/shards/%s/%d", addr, seg, idx)
}

// PutShard uploads a shard with its proof against the segment root and the
// coordinator's ticket for it.
func PutShard(ctx context.Context, hc *http.Client, addr, seg string, idx int, data []byte, proof []merkle.Hash, t *proto.Ticket) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, shardURL(addr, seg, idx), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set(ProofHeader, codec.EncodeProof(proof))
	if t != nil {
		tb, err := json.Marshal(t)
		if err != nil {
			return err
		}
		req.Header.Set(TicketHeader, base64.StdEncoding.EncodeToString(tb))
	}
	return do(hc, req, nil)
}

// GetShard fetches the shard committed under root, with its proof.
func GetShard(ctx context.Context, hc *http.Client, s Signer, addr, seg string, idx int, root string) ([]byte, []merkle.Hash, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, shardURL(addr, seg, idx)+"?root="+root, nil)
	if err != nil {
		return nil, nil, err
	}
	if s != nil {
		s.Sign(req, nil)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &HTTPError{resp.StatusCode, fmt.Sprintf("get shard %s/%d from %s: %s", seg, idx, addr, resp.Status)}
	}
	proof, err := codec.DecodeProof(resp.Header.Get(ProofHeader))
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(resp.Body)
	return data, proof, err
}

// FetchAny downloads shards until it has `need` that verify against root.
// It keeps need+2 requests in flight so one slow or dead holder doesn't stall
// the read, and cancels the stragglers once enough have arrived. The result
// has len maxN with nil for shards it didn't fetch.
func FetchAny(ctx context.Context, hc *http.Client, s Signer, seg string, locs []proto.Location, root merkle.Hash, need, maxN int) ([][]byte, error) {
	if len(locs) < need {
		return nil, fmt.Errorf("segment %.12s: %d shards reachable, need %d", seg, len(locs), need)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	queue := make(chan proto.Location, len(locs))
	for _, l := range locs {
		queue <- l
	}
	close(queue)

	type result struct {
		idx  int
		data []byte
	}
	results := make(chan result)
	var wg sync.WaitGroup
	for range min(need+2, len(locs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range queue {
				if l.Index < 0 || l.Index >= maxN {
					continue
				}
				data, proof, err := GetShard(ctx, hc, s, l.Addr, seg, l.Index, codec.HashToHex(root))
				if err != nil || !codec.VerifyShard(root, maxN, l.Index, data, proof) {
					continue // dead, slow-cancelled or lying holder: try the next one
				}
				select {
				case results <- result{l.Index, data}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()

	shards := make([][]byte, maxN)
	got := 0
	for r := range results {
		if shards[r.idx] == nil {
			shards[r.idx] = r.data
			got++
		}
		if got == need {
			return shards, nil
		}
	}
	return nil, fmt.Errorf("segment %.12s: only %d of %d needed shards verified", seg, got, need)
}

// Do sends a JSON request (in may be nil), signed by s when s is non-nil,
// and decodes the JSON response into out when out is non-nil.
func Do(ctx context.Context, hc *http.Client, s Signer, method, url string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s != nil {
		s.Sign(req, body)
	}
	return do(hc, req, out)
}

func GetJSON(ctx context.Context, hc *http.Client, s Signer, url string, out any) error {
	return Do(ctx, hc, s, http.MethodGet, url, nil, out)
}

func PostJSON(ctx context.Context, hc *http.Client, s Signer, url string, in, out any) error {
	return Do(ctx, hc, s, http.MethodPost, url, in, out)
}

func do(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return &HTTPError{resp.StatusCode, fmt.Sprintf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status, bytes.TrimSpace(b))}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
