// Package invite is how people join a pool. An admin creates an invite: a
// single string holding the coordinator's address and public key (so the
// joiner can't be pointed at an impostor), the pool secret, and a one-time
// code. The joiner's node or CLI redeems it: it generates its own keys,
// proves it holds them, and the coordinator records the new member (and
// node) in the catalog, where every node picks them up with no restarts.
//
// Treat an invite like a password until it's used: it carries the pool
// secret. The code is single-use and expires, so a leaked invite can't be
// used to join afterwards; and the secret alone doesn't let anyone fetch
// shards, since nodes only serve pool members.
package invite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"mediapool/internal/auth"
	"mediapool/internal/transfer"
)

const prefix = "mpool1."

type Invite struct {
	Coord    string `json:"c"` // coordinator base URL
	CoordKey string `json:"k"` // coordinator public key, hex
	Secret   []byte `json:"s"` // pool secret
	Code     []byte `json:"x"` // one-time code
	Name     string `json:"n,omitempty"`
	Admin    bool   `json:"a,omitempty"`
}

func New(coord, coordKey string, secret []byte, name string, admin bool) (Invite, error) {
	code := make([]byte, 16)
	if _, err := rand.Read(code); err != nil {
		return Invite{}, err
	}
	return Invite{Coord: strings.TrimRight(coord, "/"), CoordKey: coordKey, Secret: secret, Code: code, Name: name, Admin: admin}, nil
}

func (i Invite) String() string {
	b, _ := json.Marshal(i)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func Parse(s string) (Invite, error) {
	var i Invite
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), prefix)
	if !ok {
		return i, errors.New("not a mediapool invite (should start with " + prefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return i, fmt.Errorf("invite is damaged: %w", err)
	}
	if err := json.Unmarshal(b, &i); err != nil {
		return i, fmt.Errorf("invite is damaged: %w", err)
	}
	if i.Coord == "" || len(i.Code) != 16 || len(i.Secret) == 0 {
		return i, errors.New("invite is incomplete")
	}
	if k, err := hex.DecodeString(i.CoordKey); err != nil || len(k) != ed25519.PublicKeySize {
		return i, errors.New("invite has no valid coordinator key")
	}
	return i, nil
}

// Hash is what the catalog stores in place of the code.
func Hash(code []byte) string {
	h := sha256.Sum256(append([]byte("mediapool/invite/v1\n"), code...))
	return hex.EncodeToString(h[:])
}

// Pool returns the bootstrap pool file a joiner needs: just the
// coordinator's key. Members and nodes come from the catalog.
func (i Invite) Pool() *auth.Pool { return &auth.Pool{Coordinator: i.CoordKey} }

// Request is what a joiner sends to /v1/join.
type Request struct {
	Code      []byte `json:"code"`
	Member    string `json:"member"`
	MemberKey string `json:"member_key"`
	MemberSig []byte `json:"member_sig"`
	NodeID    string `json:"node_id,omitempty"`
	NodeKey   string `json:"node_key,omitempty"`
	NodeSig   []byte `json:"node_sig,omitempty"`
}

// Message is what both new keys sign, binding them to this code and these
// names so a redemption can't register someone else's keys.
func (r *Request) Message() []byte {
	return fmt.Appendf(nil, "mediapool/join/v1\n%x\n%s\n%s\n%s\n%s", r.Code, r.Member, r.MemberKey, r.NodeID, r.NodeKey)
}

// Redeem joins the pool as member (and, with nodeKey set, registers a
// storage node owned by them).
func Redeem(ctx context.Context, hc *http.Client, inv Invite, member string, memberKey ed25519.PrivateKey, nodeID string, nodeKey ed25519.PrivateKey) error {
	r := Request{Code: inv.Code, Member: member, MemberKey: auth.PubHex(memberKey)}
	if nodeKey != nil {
		r.NodeID, r.NodeKey = nodeID, auth.PubHex(nodeKey)
	}
	r.MemberSig = ed25519.Sign(memberKey, r.Message())
	if nodeKey != nil {
		r.NodeSig = ed25519.Sign(nodeKey, r.Message())
	}
	return transfer.PostJSON(ctx, hc, nil, inv.Coord+"/v1/join", r, nil)
}

// NodeAddRequest registers another node for an existing member.
type NodeAddRequest struct {
	ID  string `json:"id"`
	Key string `json:"key"`
	Sig []byte `json:"sig"` // by the node key, over NodeAddMessage
}

func NodeAddMessage(id, owner, key string) []byte {
	return []byte("mediapool/node-add/v1\n" + id + "\n" + owner + "\n" + key)
}
