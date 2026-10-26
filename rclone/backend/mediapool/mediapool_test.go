package mediapool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fstest/fstests"

	"mediapool/pkg/mediapool/mediapooltest"
)

func remoteConfig(p *mediapooltest.Pool, member string) configmap.Simple {
	c := p.Config(member)
	return configmap.Simple{
		"type": "mediapool", "coord_url": c.CoordURL, "pool_file": c.PoolFile,
		"member": c.Member, "key_file": c.KeyFile, "secret": obscure.MustObscure(c.Secret),
	}
}

func newFs(t *testing.T, p *mediapooltest.Pool, member, root string) fs.Fs {
	t.Helper()
	f, err := NewFs(context.Background(), "test", root, remoteConfig(p, member))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func put(t *testing.T, f fs.Fs, remote string, data []byte, mt time.Time) fs.Object {
	t.Helper()
	src := object.NewStaticObjectInfo(remote, mt, int64(len(data)), true, nil, nil)
	o, err := f.Put(context.Background(), bytes.NewReader(data), src)
	if err != nil {
		t.Fatalf("put %s: %v", remote, err)
	}
	return o
}

func names(entries fs.DirEntries) []string {
	var out []string
	for _, e := range entries {
		s := e.Remote()
		if _, ok := e.(fs.Directory); ok {
			s += "/"
		}
		out = append(out, s)
	}
	return out
}

func read(t *testing.T, o fs.Object, options ...fs.OpenOption) []byte {
	t.Helper()
	rc, err := o.Open(context.Background(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBackend(t *testing.T) {
	ctx := context.Background()
	p := mediapooltest.Start(t, 12)
	alice := newFs(t, p, "alice", "")
	data := make([]byte, 300<<10)
	for i := range data {
		data[i] = byte(i * 7)
	}
	mt := time.Date(2024, 5, 6, 7, 8, 9, 123456789, time.UTC)
	put(t, alice, "movies/A/a.mkv", data, mt)
	put(t, alice, "movies/b.mkv", []byte("bbb"), mt)
	put(t, alice, "top.txt", nil, mt)

	// Directory synthesis from the flat file list.
	for dir, want := range map[string]string{
		"":         "[movies/ top.txt]",
		"movies":   "[movies/A/ movies/b.mkv]",
		"movies/A": "[movies/A/a.mkv]",
	} {
		entries, err := alice.List(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(names(entries)); got != want {
			t.Errorf("List(%q) = %s, want %s", dir, got, want)
		}
	}
	if _, err := alice.List(ctx, "nope"); !errors.Is(err, fs.ErrorDirNotFound) {
		t.Errorf("List(nope) err = %v", err)
	}
	var all fs.DirEntries
	if err := alice.Features().ListR(ctx, "", func(e fs.DirEntries) error { all = append(all, e...); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(all)); got != "[movies/ movies/A/ movies/A/a.mkv movies/b.mkv top.txt]" {
		t.Errorf("ListR = %s", got)
	}

	// A sub-rooted Fs sees paths relative to its root; a file root is ErrorIsFile.
	sub := newFs(t, p, "bob", "movies")
	o, err := sub.NewObject(ctx, "A/a.mkv")
	if err != nil {
		t.Fatal(err)
	}
	if o.Size() != int64(len(data)) || !o.ModTime(ctx).Equal(mt) {
		t.Fatalf("object size %d modtime %v", o.Size(), o.ModTime(ctx))
	}
	if _, err := o.Hash(ctx, hash.MD5); !errors.Is(err, hash.ErrUnsupported) {
		t.Errorf("hash err = %v", err)
	}
	if err := o.SetModTime(ctx, time.Now()); !errors.Is(err, fs.ErrorCantSetModTime) {
		t.Errorf("SetModTime err = %v", err)
	}
	if _, err := NewFs(ctx, "test", "movies/b.mkv", remoteConfig(p, "bob")); !errors.Is(err, fs.ErrorIsFile) {
		t.Errorf("file root err = %v", err)
	}

	// Reads, whole and ranged, across segment boundaries.
	if !bytes.Equal(read(t, o), data) {
		t.Fatal("full read mismatch")
	}
	for _, opt := range []fs.OpenOption{
		&fs.RangeOption{Start: 100, End: 199},
		&fs.RangeOption{Start: 65530, End: 70000},
		&fs.RangeOption{Start: -1, End: 1000}, // last 1000 bytes
		&fs.SeekOption{Offset: 200000},
	} {
		var want []byte
		switch x := opt.(type) {
		case *fs.RangeOption:
			off, n := x.Decode(int64(len(data)))
			if n < 0 {
				n = int64(len(data)) - off
			}
			want = data[off : off+n]
		case *fs.SeekOption:
			want = data[x.Offset:]
		}
		if got := read(t, o, opt); !bytes.Equal(got, want) {
			t.Errorf("%v: got %d bytes, want %d", opt, len(got), len(want))
		}
	}

	// Only the author can overwrite or remove.
	if err := o.Remove(ctx); !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("bob remove err = %v", err)
	}
	src := object.NewStaticObjectInfo("A/a.mkv", mt, 1, true, nil, nil)
	if err := o.Update(ctx, bytes.NewReader([]byte("x")), src); !errors.Is(err, fs.ErrorPermissionDenied) {
		t.Errorf("bob update err = %v", err)
	}
	ao, err := alice.NewObject(ctx, "movies/b.mkv")
	if err != nil {
		t.Fatal(err)
	}
	mt2 := mt.Add(time.Hour)
	src = object.NewStaticObjectInfo("movies/b.mkv", mt2, 4, true, nil, nil)
	if err := ao.Update(ctx, bytes.NewReader([]byte("bbbb")), src); err != nil {
		t.Fatal(err)
	}
	if got := read(t, ao); string(got) != "bbbb" || !ao.ModTime(ctx).Equal(mt2) {
		t.Errorf("after update: %q %v", got, ao.ModTime(ctx))
	}
	if err := ao.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.NewObject(ctx, "movies/b.mkv"); !errors.Is(err, fs.ErrorObjectNotFound) {
		t.Errorf("after remove err = %v", err)
	}

	// Mkdir'd directories list until removed; non-empty ones can't be removed.
	if err := alice.Mkdir(ctx, "empty/sub"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := alice.List(ctx, ""); fmt.Sprint(names(entries)) != "[movies/ top.txt empty/]" {
		t.Errorf("List after mkdir = %s", names(entries))
	}
	if err := alice.Rmdir(ctx, "empty"); !errors.Is(err, fs.ErrorDirectoryNotEmpty) {
		t.Errorf("rmdir parent err = %v", err)
	}
	if err := alice.Rmdir(ctx, "empty/sub"); err != nil {
		t.Fatal(err)
	}
	if err := alice.Rmdir(ctx, "movies"); !errors.Is(err, fs.ErrorDirectoryNotEmpty) {
		t.Errorf("rmdir movies err = %v", err)
	}
	if err := alice.Rmdir(ctx, "nope"); !errors.Is(err, fs.ErrorDirNotFound) {
		t.Errorf("rmdir nope err = %v", err)
	}
}

// TestIntegration runs rclone's standard backend test suite against an
// in-process pool.
func TestIntegration(t *testing.T) {
	p := mediapooltest.Start(t, 12)
	c := remoteConfig(p, "alice")
	remote := fmt.Sprintf(":mediapool,coord_url='%s',pool_file='%s',member='%s',key_file='%s',secret='%s':",
		c["coord_url"], c["pool_file"], c["member"], c["key_file"], c["secret"])
	// fstests insists on finding rclone's test server scripts relative to
	// the working directory; we need none, so give it an empty set.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "fstest", "testserver", "init.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	fstests.Run(t, &fstests.Opt{
		RemoteName: remote,
		NilObject:  (*Object)(nil),
	})
}
