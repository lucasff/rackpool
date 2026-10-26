package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mediapool/internal/rc"
	"mediapool/internal/serve"
	"mediapool/internal/vfs"
)

type rcClient struct {
	t          *testing.T
	url        string
	user, pass string
}

func (r rcClient) call(path string, in any) (map[string]any, int) {
	r.t.Helper()
	b, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, r.url+"/"+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if r.user != "" {
		req.SetBasicAuth(r.user, r.pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return out, resp.StatusCode
}

func (r rcClient) ok(path string, in any) map[string]any {
	r.t.Helper()
	out, code := r.call(path, in)
	if code != http.StatusOK {
		r.t.Fatalf("%s: %d %v", path, code, out)
	}
	return out
}

func TestRCAPI(t *testing.T) {
	c := newCluster(t, 12, nil)
	s := &rc.Server{FS: vfs.New(c.client), Node: c.nodes[0], User: "u", Pass: "p", WebGUI: true, AllowLocalFiles: true}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	r := rcClient{t: t, url: srv.URL, user: "u", pass: "p"}

	if _, code := (rcClient{t: t, url: srv.URL}).call("core/version", nil); code != http.StatusUnauthorized {
		t.Fatalf("no credentials: %d", code)
	}
	caps := r.ok("core/capabilities", nil)
	if caps["library"] != true || caps["node"] != true || caps["member"] != "alice" {
		t.Fatalf("capabilities: %v", caps)
	}

	// Upload through the browser path (multipart), streamed into the pool.
	data := randomFile(t, 150<<10)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "clip.mkv")
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/operations/uploadfile?remote=/movies", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth("u", "p")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("uploadfile: %v %v", err, resp.Status)
	}
	resp.Body.Close()

	list := r.ok("operations/list", map[string]any{"remote": "/"})["list"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["Name"] != "movies" || list[0].(map[string]any)["IsDir"] != true {
		t.Fatalf("root listing: %v", list)
	}
	item := r.ok("operations/stat", map[string]any{"remote": "/movies/clip.mkv"})["item"].(map[string]any)
	if int(item["Size"].(float64)) != len(data) {
		t.Fatalf("stat: %v", item)
	}

	// Range request on /files, like a player seeking.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/files/movies/clip.mkv", nil)
	req.Header.Set("Range", "bytes=100000-100099")
	req.SetBasicAuth("u", "p")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(got, data[100000:100100]) {
		t.Fatalf("range read: %s, %d bytes", resp.Status, len(got))
	}

	// Async copy from this machine, tracked as a job.
	dir := t.TempDir()
	local := randomFile(t, 80<<10)
	os.WriteFile(filepath.Join(dir, "b.mkv"), local, 0o644)
	job := r.ok("operations/copyfile", map[string]any{"srcFs": dir, "srcRemote": "b.mkv", "dstFs": "pool:", "dstRemote": "/movies/b.mkv", "_async": true})
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := r.ok("job/status", map[string]any{"jobid": job["jobid"]})
		if st["finished"] == true {
			if st["success"] != true {
				t.Fatalf("job failed: %v", st)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job didn't finish")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.Equal(c.readBack(c.client, "/movies/b.mkv"), local) {
		t.Fatal("copyfile data mismatch")
	}
	if stats := r.ok("core/stats", nil); stats["transfers"].(float64) < 2 {
		t.Fatalf("stats didn't count transfers: %v", stats)
	}

	about := r.ok("operations/about", nil)
	if about["files"].(float64) != 2 {
		t.Fatalf("about: %v", about)
	}
	capAfter := r.ok("node/limits/set", map[string]any{"upload_limit": "80M", "quota": "5G"})
	if capAfter["upload_bps"].(float64) != 10e6 || capAfter["quota"].(float64) != 5e9 {
		t.Fatalf("limits: %v", capAfter)
	}
	if _, code := r.call("node/limits/set", map[string]any{"quota": "lots"}); code != http.StatusBadRequest {
		t.Fatalf("bad quota accepted: %d", code)
	}
	purge := r.ok("operations/purge", map[string]any{"remote": "/movies"})
	if len(purge["removed"].([]any)) != 2 {
		t.Fatalf("purge: %v", purge)
	}

	// The web UI is served, and a cross-site request is refused even with
	// valid credentials (a malicious page can't drive the rc).
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.SetBasicAuth("u", "p")
	resp, _ = http.DefaultClient.Do(req)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "<title>mediapool</title>") {
		t.Fatal("web UI not served")
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/operations/purge", strings.NewReader(`{"remote":"/"}`))
	req.Header.Set("Origin", "https://evil.example")
	req.SetBasicAuth("u", "p")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin call: %d", resp.StatusCode)
	}
}

func TestRCWithoutNodeOrLibrary(t *testing.T) {
	s := &rc.Server{}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	r := rcClient{t: t, url: srv.URL}
	if _, code := r.call("operations/list", nil); code != http.StatusNotFound {
		t.Fatalf("library call without a library: %d", code)
	}
	if _, code := r.call("node/status", nil); code != http.StatusNotFound {
		t.Fatalf("node call without a node: %d", code)
	}
	if r.ok("core/capabilities", nil)["library"] != false {
		t.Fatal("capabilities wrong")
	}
}

func TestWebDAV(t *testing.T) {
	c := newCluster(t, 12, nil)
	srv := httptest.NewServer(serve.WebDAV(vfs.New(c.client), false, t.Logf))
	defer srv.Close()
	do := func(method, path string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, body)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}
	data := randomFile(t, 130<<10)
	if resp, b := do(http.MethodPut, "/tv/Show/S01E01.mkv", bytes.NewReader(data), nil); resp.StatusCode/100 != 2 {
		t.Fatalf("PUT: %s %s", resp.Status, b)
	}
	resp, b := do("PROPFIND", "/tv/Show/", nil, map[string]string{"Depth": "1"})
	if resp.StatusCode != http.StatusMultiStatus || !strings.Contains(string(b), "S01E01.mkv") {
		t.Fatalf("PROPFIND: %s %s", resp.Status, b)
	}
	resp, b = do(http.MethodGet, "/tv/Show/S01E01.mkv", nil, map[string]string{"Range": "bytes=70000-70031"})
	if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(b, data[70000:70032]) {
		t.Fatalf("ranged GET: %s", resp.Status)
	}
	if resp, _ := do("MOVE", "/tv/Show/S01E01.mkv", nil, map[string]string{"Destination": srv.URL + "/x.mkv"}); resp.StatusCode/100 == 2 {
		t.Fatal("MOVE should be refused")
	}
	if resp, _ := do(http.MethodDelete, "/tv", nil, nil); resp.StatusCode/100 != 2 {
		t.Fatalf("DELETE: %s", resp.Status)
	}
	if _, err := c.client.Stat(c.ctx, "/tv/Show/S01E01.mkv"); err == nil {
		t.Fatal("file survived DELETE")
	}
	fmt.Fprint(io.Discard)
}
