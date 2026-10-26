package catalog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"mediapool/internal/auth"
)

// Membership entries. Every member and node is recorded here: founders as
// the catalog's first entries (written by the coordinator from pool.json),
// everyone else when they redeem an invite. So a catalog replica alone says
// who is in the pool, every node learns about joiners with no restarts, and
// nobody but the coordinator needs more than the coordinator's key.
const (
	TypeInviteCreate = "invite.create"
	TypeMemberAdd    = "member.add"
	TypeMemberRemove = "member.remove"
	TypeNodeAdd      = "node.add"
	TypeNodeRemove   = "node.remove"
	TypeNodeBridge   = "node.bridge"
)

// InviteCreate records a one-time invite. Only the code's hash is logged,
// so a catalog replica can't be used to join.
type InviteCreate struct {
	CodeHash  string `json:"code_hash"`
	By        string `json:"by"`
	Name      string `json:"name,omitempty"` // suggested member name
	Admin     bool   `json:"admin,omitempty"`
	ExpiresMs int64  `json:"expires_ms"`
}

// MemberAdd adds a member, either redeeming an invite or (Invite empty)
// directly by an admin.
type MemberAdd struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Admin  bool   `json:"admin,omitempty"`
	Invite string `json:"invite,omitempty"` // code hash it redeemed
}

type MemberRemove struct {
	Name string `json:"name"`
}

type NodeAdd struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Owner string `json:"owner"`
}

type NodeRemove struct {
	ID string `json:"id"`
}

type NodeBridge struct {
	ID     string `json:"id"`
	Bridge bool   `json:"bridge"`
}

type invite struct {
	InviteCreate
	used bool
}

type membership struct {
	members map[string]auth.Member
	nodes   map[string]auth.NodeEntry
	invites map[string]*invite
}

func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r)) {
			return false
		}
	}
	return true
}

func validKey(k string) bool {
	b, err := hex.DecodeString(k)
	return err == nil && len(b) == ed25519.PublicKeySize
}

func (m *membership) member(name string) (auth.Member, bool) {
	mm, ok := m.members[name]
	return mm, ok
}

func (m *membership) node(id string) (auth.NodeEntry, bool) {
	n, ok := m.nodes[id]
	return n, ok
}

func (m *membership) keyInUse(k string) bool {
	for _, mm := range m.members {
		if mm.Key == k {
			return true
		}
	}
	for _, n := range m.nodes {
		if n.Key == k {
			return true
		}
	}
	return false
}

func (m *membership) apply(e *Entry) (func(), bool, error) {
	decode := func(v any) error { return json.Unmarshal(e.Body, v) }
	switch e.Type {
	case TypeInviteCreate:
		var b InviteCreate
		if err := decode(&b); err != nil {
			return nil, true, err
		}
		if len(b.CodeHash) != 64 || m.invites[b.CodeHash] != nil {
			return nil, true, errors.New("bad or duplicate invite")
		}
		if by, ok := m.member(b.By); !ok || !by.Admin {
			return nil, true, fmt.Errorf("%q can't invite: not an admin", b.By)
		}
		return func() { m.invites[b.CodeHash] = &invite{InviteCreate: b} }, true, nil

	case TypeMemberAdd:
		var b MemberAdd
		if err := decode(&b); err != nil {
			return nil, true, err
		}
		if !validName(b.Name) || !validKey(b.Key) {
			return nil, true, errors.New("bad member name or key")
		}
		if _, exists := m.member(b.Name); exists {
			return nil, true, fmt.Errorf("member %q already exists", b.Name)
		}
		if m.keyInUse(b.Key) {
			return nil, true, errors.New("key already in use")
		}
		var inv *invite
		if b.Invite != "" {
			inv = m.invites[b.Invite]
			switch {
			case inv == nil:
				return nil, true, errors.New("unknown invite")
			case inv.used:
				return nil, true, errors.New("invite already used")
			case e.TimeMs > inv.ExpiresMs:
				return nil, true, errors.New("invite expired")
			case b.Admin && !inv.Admin:
				return nil, true, errors.New("invite doesn't grant admin")
			}
		}
		return func() {
			m.members[b.Name] = auth.Member{Name: b.Name, Key: b.Key, Admin: b.Admin}
			if inv != nil {
				inv.used = true
			}
		}, true, nil

	case TypeMemberRemove:
		var b MemberRemove
		if err := decode(&b); err != nil {
			return nil, true, err
		}
		if _, ok := m.members[b.Name]; !ok {
			return nil, true, fmt.Errorf("no member %q", b.Name)
		}
		return func() {
			delete(m.members, b.Name)
			for id, n := range m.nodes {
				if n.Owner == b.Name {
					delete(m.nodes, id)
				}
			}
		}, true, nil

	case TypeNodeAdd:
		var b NodeAdd
		if err := decode(&b); err != nil {
			return nil, true, err
		}
		if !validName(b.ID) || !validKey(b.Key) {
			return nil, true, errors.New("bad node id or key")
		}
		if _, ok := m.member(b.Owner); !ok {
			return nil, true, fmt.Errorf("owner %q is not a member", b.Owner)
		}
		if _, exists := m.node(b.ID); exists {
			return nil, true, fmt.Errorf("node %q already exists", b.ID)
		}
		if m.keyInUse(b.Key) {
			return nil, true, errors.New("key already in use")
		}
		return func() { m.nodes[b.ID] = auth.NodeEntry{ID: b.ID, Key: b.Key, Owner: b.Owner} }, true, nil

	case TypeNodeRemove:
		var b NodeRemove
		if err := decode(&b); err != nil {
			return nil, true, err
		}
		if _, ok := m.nodes[b.ID]; !ok {
			return nil, true, fmt.Errorf("no joined node %q", b.ID)
		}
		return func() { delete(m.nodes, b.ID) }, true, nil

	case TypeNodeBridge:
		var b NodeBridge
		if err := decode(&b); err != nil {
			return nil, true, err
		}
		n, ok := m.nodes[b.ID]
		if !ok {
			return nil, true, fmt.Errorf("no joined node %q", b.ID)
		}
		return func() { n.Bridge = b.Bridge; m.nodes[b.ID] = n }, true, nil
	}
	return nil, false, nil
}

// --- Catalog accessors (auth.Membership) -----------------------------------

func (c *Catalog) JoinedMembers() []auth.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]auth.Member, 0, len(c.state.m.members))
	for _, m := range c.state.m.members {
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b auth.Member) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (c *Catalog) JoinedNodes() []auth.NodeEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]auth.NodeEntry, 0, len(c.state.m.nodes))
	for _, n := range c.state.m.nodes {
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b auth.NodeEntry) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// InviteStatus reports whether an invite exists and can still be redeemed.
func (c *Catalog) InviteStatus(codeHash string, nowMs int64) (InviteCreate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	inv := c.state.m.invites[codeHash]
	switch {
	case inv == nil:
		return InviteCreate{}, errors.New("unknown invite")
	case inv.used:
		return inv.InviteCreate, errors.New("invite already used")
	case nowMs > inv.ExpiresMs:
		return inv.InviteCreate, errors.New("invite expired")
	}
	return inv.InviteCreate, nil
}
