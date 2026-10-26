package integration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/catalog"
	"mediapool/internal/client"
	"mediapool/internal/invite"
	"mediapool/internal/node"
	"mediapool/internal/transfer"
)

func (c *cluster) createInvite(admin, name string, adminInvite bool) invite.Invite {
	c.t.Helper()
	inv, err := invite.New(c.url, auth.PubHex(c.coordKey), secret, name, adminInvite)
	if err != nil {
		c.t.Fatal(err)
	}
	err = transfer.PostJSON(c.ctx, http.DefaultClient, auth.NewIdentity(c.members[admin]), c.url+"/v1/invites",
		catalog.InviteCreate{CodeHash: invite.Hash(inv.Code), Name: name, Admin: adminInvite, ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	return inv
}

// startJoinedNode runs a node that knows nothing but what the invite gave it.
func (c *cluster) startJoinedNode(inv invite.Invite, id string, key ed25519.PrivateKey) *node.Node {
	c.t.Helper()
	h := &deferredHandler{}
	srv := httptest.NewServer(h)
	c.t.Cleanup(srv.Close)
	n, err := node.New(node.Config{ID: id, Addr: srv.URL, DataDir: c.t.TempDir(), CoordURL: inv.Coord, Key: key, Pool: inv.Pool(), Logf: c.t.Logf})
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { n.Close() })
	h.h = n.Handler()
	c.direct[n] = h
	c.nodes = append(c.nodes, n)
	return n
}

func TestJoinWithInvite(t *testing.T) {
	c := newCluster(t, 12, nil)
	data := randomFile(t, 60<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/movies/A.mkv", nil); err != nil {
		t.Fatal(err)
	}

	// Only admins invite.
	bobInv, _ := invite.New(c.url, auth.PubHex(c.coordKey), secret, "x", false)
	err := transfer.PostJSON(c.ctx, http.DefaultClient, auth.NewIdentity(c.members["bob"]), c.url+"/v1/invites",
		catalog.InviteCreate{CodeHash: invite.Hash(bobInv.Code)}, nil)
	var he *transfer.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusForbidden {
		t.Fatalf("non-admin invite: %v", err)
	}

	inv := c.createInvite("alice", "dave", false)
	token := inv.String()
	parsed, err := invite.Parse(token)
	if err != nil {
		t.Fatal(err)
	}

	daveKey, nodeKey := auth.Generate(), auth.Generate()
	if err := invite.Redeem(c.ctx, http.DefaultClient, parsed, "dave", daveKey, "dave-nas", nodeKey); err != nil {
		t.Fatal(err)
	}
	// Single use.
	if err := invite.Redeem(c.ctx, http.DefaultClient, parsed, "eve", auth.Generate(), "", nil); err == nil {
		t.Fatal("invite redeemed twice")
	}

	// Dave's node joins with only the invite's bootstrap pool, and the
	// coordinator accepts it without a restart.
	dn := c.startJoinedNode(parsed, "dave-nas", nodeKey)
	c.cycle(2)
	online := false
	for _, n := range c.coord.Status().Nodes {
		if n.ID == "dave-nas" && n.Online && n.Owner == "dave" {
			online = true
		}
	}
	if !online {
		t.Fatalf("joined node not online: %+v", c.coord.Status().Nodes)
	}
	// Existing nodes learned about dave from their catalog replicas, so they
	// serve his requests.
	dave, err := client.New(parsed.Coord, parsed.Secret, "dave", daveKey, parsed.Pool(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.readBack(dave, "/movies/A.mkv"), data) {
		t.Fatal("joined member can't read")
	}
	if _, err := dave.Add(c.ctx, bytes.NewReader(randomFile(t, 10<<10)), "/dave/x.mkv", nil); err != nil {
		t.Fatalf("joined member can't add: %v", err)
	}
	// And other members' replicas accept his signed file entries.
	if _, err := c.client.Stat(c.ctx, "/dave/x.mkv"); err != nil {
		t.Fatalf("alice doesn't see dave's file: %v", err)
	}

	// An admin removes dave: his node and his client are cut off.
	if err := transfer.PostJSON(c.ctx, http.DefaultClient, auth.NewIdentity(c.members["alice"]), c.url+"/v1/members/remove", catalog.MemberRemove{Name: "dave"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := dn.HeartbeatOnce(c.ctx); err == nil {
		t.Fatal("removed member's node still heartbeats")
	}
	if _, err := dave.Add(c.ctx, bytes.NewReader([]byte("x")), "/dave/y", nil); err == nil {
		t.Fatal("removed member can still write")
	}
}

// A member who just joined is served immediately, not after every node's
// next heartbeat.
func TestJustJoinedMemberIsServed(t *testing.T) {
	c := newCluster(t, 12, nil)
	data := randomFile(t, 60<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x.mkv", nil); err != nil {
		t.Fatal(err)
	}
	c.cycle(2)
	inv := c.createInvite("alice", "gina", false)
	key := auth.Generate()
	if err := invite.Redeem(c.ctx, http.DefaultClient, inv, "gina", key, "", nil); err != nil {
		t.Fatal(err)
	}
	// No heartbeats from here on: nodes only know gina if they catch up on demand.
	gina, err := client.New(inv.Coord, inv.Secret, "gina", key, inv.Pool(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.readBack(gina, "/x.mkv"), data) {
		t.Fatal("mismatch")
	}
}
