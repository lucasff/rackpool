package integration

import (
	"bytes"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mediapool/internal/node"
	"mediapool/internal/rc"
	"mediapool/internal/vfs"
)

// linkFile writes data into n's link root and links it into the pool as
// member owner, from n.
func (c *cluster) linkFile(n *node.Node, owner, name, poolPath string, data []byte) {
	c.t.Helper()
	p := filepath.Join(n.LinkRoot(), name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		c.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		c.t.Fatal(err)
	}
	st, err := c.newClient(owner).LinkFile(c.ctx, n, p, poolPath)
	if err != nil {
		c.t.Fatal(err)
	}
	if st.Linked != st.Segments || st.Deduped != 0 {
		c.t.Fatalf("link %s: %+v", name, st)
	}
}

// storedShards counts shard files on disk across the pool, ignoring the
// regenerated shards linked segments report.
func (c *cluster) storedShards() int {
	total := 0
	for _, n := range c.nodes {
		_ = filepath.WalkDir(filepath.Join(n.DataDir(), "shards"), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && !strings.HasSuffix(p, ".proof") {
				total++
			}
			return nil
		})
	}
	return total
}

func TestLinkedFileIsReadableWithoutStoringShards(t *testing.T) {
	c := newCluster(t, 6, nil)
	origin := c.nodes[0] // owned by op00
	data := randomFile(t, 200<<10)
	c.linkFile(origin, "op00", "Movies/A (2001)/a.mkv", "/movies/a.mkv", data)

	if got := c.storedShards(); got != 0 {
		t.Fatalf("linking stored %d shards; want none", got)
	}
	if origin.Links() != 4 {
		t.Fatalf("origin links %d segments, want 4", origin.Links())
	}

	// Every member sees and reads it: the pool view is the union.
	if !bytes.Equal(c.readBack(c.client, "/movies/a.mkv"), data) {
		t.Fatal("alice read back different bytes")
	}

	// The scheduler leaves linked segments alone: no repair into the pool.
	c.cycle(8)
	if got := c.storedShards(); got != 0 {
		t.Fatalf("scheduler copied %d shards of a linked file into the pool", got)
	}
	for _, s := range c.coord.Status().Segments {
		if s.Class != "linked" || s.Durable != c.cfg.Params.K {
			t.Fatalf("segment status %+v", s)
		}
	}

	// Another member uploading the same bytes dedups onto the linked
	// segments and uploads nothing.
	st, err := c.newClient("bob").Add(c.ctx, bytes.NewReader(data), "/bob/a copy.mkv", nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Deduped != 4 || st.Uploaded != 0 {
		t.Fatalf("upload of linked bytes should dedup fully: %+v", st)
	}
}

func TestLinkedFileFollowsOriginAvailability(t *testing.T) {
	c := newCluster(t, 6, nil)
	origin := c.nodes[1]
	data := randomFile(t, 70<<10) // two segments
	c.linkFile(origin, "op01", "b.mkv", "/b.mkv", data)

	c.pause(origin)
	c.cycle(3)
	m, err := c.client.Stat(c.ctx, "/b.mkv")
	if err != nil {
		t.Fatal(err) // still listed: the catalog has it
	}
	if _, err := io.ReadAll(c.client.Open(c.ctx, m)); err == nil {
		t.Fatal("read a linked file while its origin was offline")
	}

	c.resume(origin)
	c.cycle(2)
	if !bytes.Equal(c.readBack(c.newClient("bob"), "/b.mkv"), data) {
		t.Fatal("read back different bytes after the origin returned")
	}
}

func TestCantLinkFromSomeoneElsesNode(t *testing.T) {
	c := newCluster(t, 6, nil)
	n := c.nodes[2] // owned by op02
	p := filepath.Join(n.LinkRoot(), "c.mkv")
	if err := os.WriteFile(p, randomFile(t, 10<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := c.client.LinkFile(c.ctx, n, p, "/c.mkv") // alice, not op02
	if err == nil || !strings.Contains(err.Error(), "own nodes") {
		t.Fatalf("linking from another member's node: err = %v", err)
	}
}

func TestLinkRefusesFilesOutsideTheRoot(t *testing.T) {
	c := newCluster(t, 6, nil)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("not for the pool"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := c.newClient("op00").LinkFile(c.ctx, c.nodes[0], outside, "/x")
	if err == nil || !strings.Contains(err.Error(), "outside the link root") {
		t.Fatalf("err = %v", err)
	}
}

func TestChangedLinkedFileIsNotServed(t *testing.T) {
	c := newCluster(t, 6, nil)
	origin := c.nodes[3]
	data := randomFile(t, 30<<10)
	c.linkFile(origin, "op03", "d.mkv", "/d.mkv", data)

	// Overwrite in place (same size). The origin must refuse to serve bytes
	// that no longer match, and readers must not get wrong data.
	if err := os.WriteFile(filepath.Join(origin.LinkRoot(), "d.mkv"), randomFile(t, 30<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	// Push d.mkv's segment out of the origin's regeneration cache, so the
	// next read has to go back to the (changed) file.
	c.linkFile(origin, "op03", "filler.mkv", "/filler.mkv", randomFile(t, 6*64<<10))

	reader := c.newClient("bob") // fresh client: nothing cached
	m, err := reader.Stat(c.ctx, "/d.mkv")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader.Open(c.ctx, m))
	if err == nil {
		if bytes.Equal(got, data) {
			t.Fatal("served the original bytes from a file that changed: cache wasn't evicted")
		}
		t.Fatal("served changed bytes for a linked file")
	}
}

// node/link over the rc API: link a whole directory tree from the node's link
// root, skipping macOS metadata files, and read it back as another member.
func TestRCLinkDirectory(t *testing.T) {
	c := newCluster(t, 6, nil)
	n := c.nodes[0]
	s := &rc.Server{FS: vfs.New(c.newClient("op00")), Node: n, User: "u", Pass: "p"}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	r := rcClient{t: t, url: srv.URL, user: "u", pass: "p"}

	files := map[string][]byte{
		"Movies/A (2001)/a.mkv":    randomFile(t, 100<<10),
		"Movies/A (2001)/a.en.srt": randomFile(t, 3<<10),
		"Shows/B/S01/e01.mkv":      randomFile(t, 70<<10),
	}
	for name, data := range files {
		p := filepath.Join(n.LinkRoot(), name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, data, 0o644)
	}
	os.WriteFile(filepath.Join(n.LinkRoot(), "Movies", "._a.mkv"), []byte("appledouble"), 0o644)

	out := r.ok("node/link", map[string]any{"src": "/", "dst": "/library"})
	if out["files"] != float64(3) || out["deduped"] != float64(0) || len(out["failed"].([]any)) != 0 {
		t.Fatalf("node/link: %v", out)
	}
	if got := c.storedShards(); got != 0 {
		t.Fatalf("linking stored %d shards", got)
	}
	for name, data := range files {
		if !bytes.Equal(c.readBack(c.client, "/library/"+name), data) {
			t.Fatalf("%s: read back different bytes", name)
		}
	}
	if _, err := c.client.Stat(c.ctx, "/library/Movies/._a.mkv"); err == nil {
		t.Fatal("linked a ._ metadata file")
	}

	// Linking again is idempotent: everything dedups.
	out = r.ok("node/link", map[string]any{"src": "Movies", "dst": "/library/Movies"})
	if out["files"] != float64(2) || out["linked"] != float64(0) {
		t.Fatalf("relink: %v", out)
	}
}
