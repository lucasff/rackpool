// Package proto holds the JSON messages exchanged between nodes, clients and
// the coordinator. The coordinator only ever sees ciphertext hashes, shard
// locations and sealed blobs.
package proto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"mediapool/internal/catalog"
	"mediapool/internal/codec"
)

// CoordSigHeader carries the coordinator's signature over a heartbeat
// response, so a node only acts on tasks and deletes that really came from it.
const CoordSigHeader = "X-Coord-Sig"

func HeartbeatSigMessage(nodeID string, body []byte) []byte {
	return append([]byte("mediapool/heartbeat-response/v1\n"+nodeID+"\n"), body...)
}

type NodeInfo struct {
	ID       string   `json:"id"`
	Addr     string   `json:"addr"` // base URL of the node's shard API
	Capacity Capacity `json:"capacity"`
	// Reach is how Addr was established: "direct" (dial-back confirmed),
	// "mapped" (router port mapping, dial-back confirmed), "relay" (behind
	// CGNAT or unreachable; traffic goes through a relay), or "" (unchecked).
	Reach string `json:"reach,omitempty"`
}

// ProbeRequest asks the coordinator to dial candidate addresses back.
type ProbeRequest struct {
	Candidates []string `json:"candidates"`
}

type ProbeResponse struct {
	Reachable []string          `json:"reachable"`
	Errors    map[string]string `json:"errors,omitempty"`
}

// PingResponse proves the node at an address holds a given key.
type PingResponse struct {
	ID  string `json:"id"`
	Sig []byte `json:"sig"`
}

func PingSigMessage(nodeID, nonce string) []byte {
	return []byte("mediapool/ping/v1\n" + nodeID + "\n" + nonce)
}

// Capacity is what an operator offers the pool, reported every heartbeat.
// The node enforces it on its own; the coordinator uses it to place within
// it. Free is -1 when unknown.
type Capacity struct {
	Quota       int64 `json:"quota"`
	Used        int64 `json:"used"`
	Free        int64 `json:"free"`
	Drain       bool  `json:"drain"`
	UploadBps   int64 `json:"upload_bps"`
	DownloadBps int64 `json:"download_bps"`
}

// ShardKey names a stored shard. Root pins which upload of the segment it
// belongs to, so a junk upload under a real segment ID can never be confused
// with, or overwrite, the committed shards.
type ShardKey struct {
	Segment string `json:"segment"`
	Index   int    `json:"index"`
	Root    string `json:"root"`
}

type Location struct {
	Index  int    `json:"index"`
	NodeID string `json:"node_id"`
	Addr   string `json:"addr"`
}

// Ticket is the coordinator's permission to store one shard on one node.
// Nodes refuse uploads without one, and check the shard against Root.
type Ticket struct {
	Segment    string `json:"segment"`
	Index      int    `json:"index"`
	NodeID     string `json:"node_id"`
	Root       string `json:"root"`
	CipherSize int    `json:"cipher_size"`
	K          int    `json:"k"`
	MaxN       int    `json:"max_n"`
	ExpMs      int64  `json:"exp_ms"`
	Sig        []byte `json:"sig"`
}

func (t *Ticket) signedBytes() []byte {
	return fmt.Appendf(nil, "mediapool/upload-ticket/v1\n%s\n%d\n%s\n%s\n%d\n%d\n%d\n%d",
		t.Segment, t.Index, t.NodeID, t.Root, t.CipherSize, t.K, t.MaxN, t.ExpMs)
}

func (t *Ticket) Sign(priv ed25519.PrivateKey) { t.Sig = ed25519.Sign(priv, t.signedBytes()) }

func (t *Ticket) Params() codec.Params { return codec.Params{K: t.K, MaxN: t.MaxN} }

// Check verifies that the ticket is signed by the coordinator and covers
// exactly this shard on this node.
func (t *Ticket) Check(coord ed25519.PublicKey, nodeID, seg string, idx int, now time.Time) error {
	switch {
	case !ed25519.Verify(coord, t.signedBytes(), t.Sig):
		return errors.New("ticket not signed by the coordinator")
	case t.NodeID != nodeID || t.Segment != seg || t.Index != idx:
		return errors.New("ticket is for another shard or node")
	case now.UnixMilli() > t.ExpMs:
		return errors.New("ticket expired")
	}
	return t.Params().Validate()
}

type PutTarget struct {
	Location
	Ticket Ticket `json:"ticket"`
}

type HeartbeatRequest struct {
	Node      NodeInfo     `json:"node"`
	Head      catalog.Head `json:"head"`
	Inventory []ShardKey   `json:"inventory"`
}

type HeartbeatResponse struct {
	Head         catalog.Head  `json:"head"`
	Ready        bool          `json:"ready"` // coordinator has confirmed its catalog against the pool
	Tasks        []Task        `json:"tasks,omitempty"`
	Deletes      []ShardKey    `json:"deletes,omitempty"`
	HealthChecks []HealthCheck `json:"health_checks,omitempty"` // bridges only
}

// Task asks a node to produce shards and push them to other nodes. With Fetch
// set it rebuilds from pool shards; with SourceBlob set (bridges only) it
// rebuilds from the segment's external torrent source.
type Task struct {
	ID         string       `json:"id"`
	Segment    string       `json:"segment"`
	CipherSize int          `json:"cipher_size"`
	Params     codec.Params `json:"params"`
	Root       string       `json:"root"`
	Fetch      []Location   `json:"fetch,omitempty"`
	SourceBlob []byte       `json:"source_blob,omitempty"`
	Move       *Location    `json:"move,omitempty"` // copy this one shard as-is
	Put        []PutTarget  `json:"put"`
}

type TaskResult struct {
	TaskID string     `json:"task_id"`
	Placed []Location `json:"placed"`
	Error  string     `json:"error,omitempty"`
}

// HealthCheck asks a bridge about a segment's external swarm. With Verify set
// the bridge must rebuild the segment from the swarm and match its ID; a
// plain liveness check can keep a segment anchored but never anchor it.
type HealthCheck struct {
	Segment    string `json:"segment"`
	SourceBlob []byte `json:"source_blob"`
	Verify     bool   `json:"verify"`
}

type SwarmReport struct {
	Segment  string `json:"segment"`
	Healthy  bool   `json:"healthy"`
	Verified bool   `json:"verified"` // the bridge rebuilt this exact segment from the swarm
}

type PrepareRequest struct {
	Segment    string `json:"segment"`
	CipherSize int    `json:"cipher_size"`
	Root       string `json:"root"`
	SourceBlob []byte `json:"source_blob,omitempty"`
}

type PrepareResponse struct {
	Exists  bool        `json:"exists"`
	Targets []PutTarget `json:"targets,omitempty"`
}

type CommitRequest struct {
	Segment string     `json:"segment"`
	Root    string     `json:"root"`
	Placed  []Location `json:"placed"`
}

type FilePutRequest struct {
	PathID   string   `json:"path_id"`
	Segments []string `json:"segments"`
	Manifest []byte   `json:"manifest"`
}

type LocateResponse struct {
	Segment    string       `json:"segment"`
	Root       string       `json:"root"`
	CipherSize int          `json:"cipher_size"`
	Params     codec.Params `json:"params"`
	Shards     []Location   `json:"shards"`
}

// ProofResponse answers a storage challenge for one chunk of one shard. The
// node signs it over the challenge nonce, so a node can't earn credit by
// pointing the coordinator at someone else's disk.
type ProofResponse struct {
	ShardHash  string `json:"shard_hash"`
	SegProof   string `json:"seg_proof"`
	Chunk      []byte `json:"chunk"`
	ChunkProof string `json:"chunk_proof"`
	Sig        []byte `json:"sig"`
}

func ProofSigMessage(nonce, seg string, idx int, root string, chunk int, data []byte) []byte {
	h := sha256.Sum256(data)
	return fmt.Appendf(nil, "mediapool/storage-proof/v1\n%s\n%s\n%d\n%s\n%d\n%x", nonce, seg, idx, root, chunk, h)
}

type NodeStatus struct {
	ID       string    `json:"id"`
	Owner    string    `json:"owner"`
	Addr     string    `json:"addr"`
	Bridge   bool      `json:"bridge"`
	Online   bool      `json:"online"`
	Shards   int       `json:"shards"`
	Strikes  int       `json:"strikes"`
	FailProb float64   `json:"fail_prob"`
	Capacity Capacity  `json:"capacity"`
	Reach    string    `json:"reach,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

type SegmentStatus struct {
	ID         string  `json:"id"`
	Class      string  `json:"class"`
	Refs       int     `json:"refs"`
	Target     int     `json:"target"`
	Durable    int     `json:"durable"`
	Online     int     `json:"online"`
	HeatPerMin float64 `json:"heat_per_min"`
	LossProb   float64 `json:"loss_prob"`
	Repairing  bool    `json:"repairing"`
}

type StatusResponse struct {
	Params       codec.Params    `json:"params"`
	Head         catalog.Head    `json:"head"`
	WriteBlocked string          `json:"write_blocked,omitempty"`
	Nodes        []NodeStatus    `json:"nodes"`
	Segments     []SegmentStatus `json:"segments"`
}
