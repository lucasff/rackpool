// Package auth holds pool identities. Every coordinator request is signed
// by a member or node key listed in the pool file, and the coordinator signs
// the catalog, upload tickets and heartbeat responses with its own key. The
// pool secret only encrypts content: knowing it doesn't let anyone speak for
// the coordinator or another member.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const scheme = "MP1"

var ErrUnauthenticated = errors.New("auth: unauthenticated")

// Identity signs outgoing requests.
type Identity struct{ priv ed25519.PrivateKey }

func NewIdentity(priv ed25519.PrivateKey) *Identity { return &Identity{priv: priv} }

func (id *Identity) Public() ed25519.PublicKey { return id.priv.Public().(ed25519.PublicKey) }

func (id *Identity) KeyID() string { return hex.EncodeToString(id.Public()) }

func message(method, uri, ts, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte("mediapool/request/v1\n" + method + "\n" + uri + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(h[:]))
}

// Sign adds an Authorization header covering the method, URI, time, a
// random nonce and the body.
func (id *Identity) Sign(req *http.Request, body []byte) {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	nb := make([]byte, 12)
	_, _ = rand.Read(nb)
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	sig := ed25519.Sign(id.priv, message(req.Method, req.URL.RequestURI(), ts, nonce, body))
	req.Header.Set("Authorization", fmt.Sprintf("%s %s %s %s %s", scheme, id.KeyID(), ts, nonce, base64.RawURLEncoding.EncodeToString(sig)))
}

// SignRaw signs an application message (catalog file entries).
func (id *Identity) SignRaw(msg []byte) []byte { return ed25519.Sign(id.priv, msg) }

// Signer returns a function that signs a bodiless request.
func (id *Identity) Signer() func(*http.Request) { return func(r *http.Request) { id.Sign(r, nil) } }

// Verifier checks signed requests and rejects replays within the skew window.
type Verifier struct {
	Skew time.Duration

	mu        sync.Mutex
	seen      map[string]time.Time
	lastPrune time.Time
}

func (v *Verifier) Verify(r *http.Request, body []byte) (ed25519.PublicKey, error) {
	return v.VerifyURI(r, r.URL.RequestURI(), body)
}

// VerifyURI is Verify for a request whose signed URI differs from the one
// it arrived with (a relay strips its own path prefix).
func (v *Verifier) VerifyURI(r *http.Request, uri string, body []byte) (ed25519.PublicKey, error) {
	f := strings.Fields(r.Header.Get("Authorization"))
	if len(f) != 5 || f[0] != scheme {
		return nil, fmt.Errorf("%w: missing or malformed Authorization header", ErrUnauthenticated)
	}
	pub, err := hex.DecodeString(f[1])
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: bad key id", ErrUnauthenticated)
	}
	ms, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad timestamp", ErrUnauthenticated)
	}
	nonce := f[3]
	if len(nonce) < 16 || len(nonce) > 64 {
		return nil, fmt.Errorf("%w: bad nonce", ErrUnauthenticated)
	}
	sig, err := base64.RawURLEncoding.DecodeString(f[4])
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrUnauthenticated)
	}
	skew := v.Skew
	if skew == 0 {
		skew = 2 * time.Minute
	}
	now := time.Now()
	if d := now.Sub(time.UnixMilli(ms)); d > skew || d < -skew {
		return nil, fmt.Errorf("%w: timestamp outside the %v window", ErrUnauthenticated, skew)
	}
	if !ed25519.Verify(pub, message(r.Method, uri, f[2], nonce, body), sig) {
		return nil, fmt.Errorf("%w: bad signature", ErrUnauthenticated)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]time.Time{}
	}
	if now.Sub(v.lastPrune) > skew {
		for s, exp := range v.seen {
			if now.After(exp) {
				delete(v.seen, s)
			}
		}
		v.lastPrune = now
	}
	replayKey := f[1] + "/" + nonce
	if _, dup := v.seen[replayKey]; dup {
		return nil, fmt.Errorf("%w: replayed request", ErrUnauthenticated)
	}
	v.seen[replayKey] = now.Add(2 * skew)
	return pub, nil
}

// Pool is the public membership file every participant shares. It holds
// public keys only.
type Pool struct {
	Coordinator string      `json:"coordinator"`
	Members     []Member    `json:"members"`
	Nodes       []NodeEntry `json:"nodes"`
}

type Member struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// NodeEntry registers a storage node under the member who runs it. Placement
// treats every node of one owner as a single failure domain, so extra nodes
// buy an owner no extra share of any segment. Bridge is an operator role the
// pool grants, not something a node can claim for itself.
type NodeEntry struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Owner  string `json:"owner"`
	Bridge bool   `json:"bridge,omitempty"`
}

// Principal is who signed a request: exactly one of Member or Node is set.
type Principal struct {
	Member string
	Node   *NodeEntry
}

func LoadPool(path string) (*Pool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Pool
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("auth: %s: %w", path, err)
	}
	return &p, p.Validate()
}

func (p *Pool) Validate() error {
	if _, err := p.CoordinatorKey(); err != nil {
		return err
	}
	keys, names, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	claim := func(k string) error {
		if b, err := hex.DecodeString(k); err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("auth: bad public key %q", k)
		}
		if keys[k] {
			return fmt.Errorf("auth: key %.12s listed twice", k)
		}
		keys[k] = true
		return nil
	}
	for _, m := range p.Members {
		if m.Name == "" || names[m.Name] {
			return fmt.Errorf("auth: member name %q empty or duplicated", m.Name)
		}
		names[m.Name] = true
		if err := claim(m.Key); err != nil {
			return err
		}
	}
	for _, n := range p.Nodes {
		if n.ID == "" || ids[n.ID] {
			return fmt.Errorf("auth: node id %q empty or duplicated", n.ID)
		}
		if !names[n.Owner] {
			return fmt.Errorf("auth: node %s owner %q is not a member", n.ID, n.Owner)
		}
		ids[n.ID] = true
		if err := claim(n.Key); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pool) CoordinatorKey() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(p.Coordinator)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("auth: pool file has no valid coordinator key")
	}
	return b, nil
}

// MemberKey returns a member's public key, or nil.
func (p *Pool) MemberKey(name string) ed25519.PublicKey {
	for _, m := range p.Members {
		if m.Name == name {
			b, _ := hex.DecodeString(m.Key)
			return b
		}
	}
	return nil
}

func (p *Pool) Node(id string) (NodeEntry, bool) {
	for _, n := range p.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return NodeEntry{}, false
}

func (p *Pool) Lookup(pub ed25519.PublicKey) (Principal, bool) {
	k := hex.EncodeToString(pub)
	for _, m := range p.Members {
		if m.Key == k {
			return Principal{Member: m.Name}, true
		}
	}
	for i := range p.Nodes {
		if p.Nodes[i].Key == k {
			return Principal{Node: &p.Nodes[i]}, true
		}
	}
	return Principal{}, false
}

func PubHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func Generate() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}

// LoadOrCreateKey reads a hex-encoded ed25519 seed, creating one if the file
// doesn't exist.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		priv := Generate()
		return priv, os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600)
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("auth: %s is not a hex ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
