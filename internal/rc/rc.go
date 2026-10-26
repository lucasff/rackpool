// Package rc is the remote-control API, modelled on rclone's: every call is
// POST /<group>/<method> with parameters as JSON (or query/form values),
// answered with a JSON object. The CLI's `mp rc` command, scripts and the
// built-in web UI all drive a running `mp rcd` or `mp-node` through it.
//
// Calls are grouped by what the process has: operations/* and pool/* need
// member credentials (a library), node/* need a storage node in-process.
// core/capabilities says which are available.
package rc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"mediapool/internal/limits"
	"mediapool/internal/node"
	"mediapool/internal/stats"
	"mediapool/internal/vfs"
)

// Version is set by main.
var Version = "dev"

//go:embed web
var webFiles embed.FS

type Params map[string]any

type Server struct {
	FS    *vfs.FS    // library calls; nil without member credentials
	Node  *node.Node // node calls; nil unless running inside mp-node
	Stats *stats.Stats

	User, Pass string // basic auth; empty disables it (loopback only, enforced by callers)
	WebGUI     bool
	// AllowLocalFiles permits operations/copyfile to read and write this
	// machine's filesystem, as rclone's rc does. Off unless auth is on.
	AllowLocalFiles bool

	jobsMu sync.Mutex
	jobs   map[int64]*job
	jobSeq int64
}

type call struct {
	help  string
	needs string // "", "fs" or "node"
	fn    func(ctx context.Context, s *Server, in Params) (Params, error)
}

var calls map[string]call

func init() {
	calls = map[string]call{
		"rc/noop":               {help: "Echo the parameters back.", fn: func(_ context.Context, _ *Server, in Params) (Params, error) { return in, nil }},
		"rc/list":               {help: "List all calls.", fn: rcList},
		"core/version":          {help: "Version and platform.", fn: coreVersion},
		"core/capabilities":     {help: "Which call groups this process serves.", fn: coreCapabilities},
		"core/stats":            {help: "Transfer statistics.", fn: func(_ context.Context, s *Server, _ Params) (Params, error) { return toParams(s.Stats.Snapshot()) }},
		"core/stats-reset":      {help: "Reset transfer statistics.", fn: func(_ context.Context, s *Server, _ Params) (Params, error) { s.Stats.Reset(); return Params{}, nil }},
		"job/list":              {help: "List job IDs.", fn: jobList},
		"job/status":            {help: "Status of a job. Params: jobid.", fn: jobStatus},
		"job/stop":              {help: "Cancel a running job. Params: jobid.", fn: jobStop},
		"operations/list":       {needs: "fs", help: "List a directory. Params: remote, opt.recurse (bool).", fn: opList},
		"operations/stat":       {needs: "fs", help: "Stat a file or directory. Params: remote.", fn: opStat},
		"operations/about":      {needs: "fs", help: "Library and pool totals.", fn: opAbout},
		"operations/deletefile": {needs: "fs", help: "Delete a file you added. Params: remote.", fn: opDeleteFile},
		"operations/purge":      {needs: "fs", help: "Delete every file you added under a directory. Params: remote, dryRun.", fn: opPurge},
		"operations/copyfile":   {needs: "fs", help: "Copy one file between this machine and the pool. Params: srcFs, srcRemote, dstFs, dstRemote; an fs is \"pool:\" or a local directory.", fn: opCopyFile},
		"operations/uploadfile": {needs: "fs", help: "Upload multipart/form-data files into directory `remote`.", fn: nil},
		"pool/status":           {needs: "fs", help: "The coordinator's view: nodes, capacity, segments.", fn: poolStatus},
		"node/status":           {needs: "node", help: "This node's address, reachability and capacity.", fn: nodeStatus},
		"node/limits/set":       {needs: "node", help: "Change limits until restart. Params (all optional): quota, upload_limit, download_limit (\"50M\" = 50 Mbit/s), drain (bool).", fn: nodeLimitsSet},
	}
}

func (s *Server) has(needs string) bool {
	switch needs {
	case "fs":
		return s.FS != nil
	case "node":
		return s.Node != nil
	}
	return true
}

// Handler serves the API, /files/<path> for streaming pool files, and the
// web UI at / when enabled.
func (s *Server) Handler() http.Handler {
	if s.Stats == nil {
		s.Stats = stats.New()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/files/", s.serveFile)
	mux.HandleFunc("/", s.serve)
	return s.guard(mux)
}

// guard enforces basic auth and rejects cross-site requests, so a web page
// open in the operator's browser can't drive their rc with cached
// credentials.
func (s *Server) guard(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		if s.User != "" {
			u, p, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(s.User)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(s.Pass)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="mediapool"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(r.URL.Path, "/")
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if !s.WebGUI {
			http.NotFound(w, r)
			return
		}
		sub, _ := fs.Sub(webFiles, "web")
		if name == "" {
			name = "index.html"
		}
		b, err := fs.ReadFile(sub, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		_, _ = w.Write(b)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	c, ok := calls[name]
	if !ok {
		writeErr(w, name, nil, http.StatusNotFound, fmt.Errorf("couldn't find method %q", name))
		return
	}
	if !s.has(c.needs) {
		writeErr(w, name, nil, http.StatusNotFound, fmt.Errorf("%s isn't available here (needs %s)", name, map[string]string{"fs": "member credentials", "node": "a storage node"}[c.needs]))
		return
	}
	if name == "operations/uploadfile" {
		s.uploadFile(w, r)
		return
	}
	in, err := readParams(r)
	if err != nil {
		writeErr(w, name, in, http.StatusBadRequest, err)
		return
	}
	if async, _ := in["_async"].(bool); async {
		delete(in, "_async")
		id := s.startJob(name, c, in)
		writeJSON(w, Params{"jobid": id})
		return
	}
	out, err := c.fn(r.Context(), s, in)
	if err != nil {
		writeErr(w, name, in, statusFor(err), err)
		return
	}
	if out == nil {
		out = Params{}
	}
	writeJSON(w, out)
}

func readParams(r *http.Request) (Params, error) {
	in := Params{}
	for k, v := range r.URL.Query() {
		in[k] = v[0]
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch ct {
	case "application/json":
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return in, err
		}
		if len(strings.TrimSpace(string(body))) > 0 {
			var j Params
			if err := json.Unmarshal(body, &j); err != nil {
				return in, fmt.Errorf("bad JSON: %w", err)
			}
			for k, v := range j {
				in[k] = v
			}
		}
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return in, err
		}
		for k, v := range r.PostForm {
			in[k] = v[0]
		}
	}
	// Query/form values arrive as strings; accept "true" for booleans.
	for k, v := range in {
		if sv, ok := v.(string); ok && (sv == "true" || sv == "false") && (k == "_async" || k == "dryRun" || k == "drain") {
			in[k] = sv == "true"
		}
	}
	return in, nil
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, errBadParam):
		return http.StatusBadRequest
	case errors.Is(err, os.ErrPermission):
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

var errBadParam = errors.New("bad parameter")

func str(in Params, k string, required bool) (string, error) {
	v, ok := in[k]
	if !ok {
		if required {
			return "", fmt.Errorf("%w: %q is required", errBadParam, k)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q must be a string", errBadParam, k)
	}
	return s, nil
}

func boolean(in Params, k string) bool {
	switch v := in[k].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, path string, in Params, status int, err error) {
	w.WriteHeader(status)
	writeJSON(w, Params{"error": err.Error(), "path": path, "input": in, "status": status})
}

func toParams(v any) (Params, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var p Params
	return p, json.Unmarshal(b, &p)
}

// --- core, rc, job ----------------------------------------------------------

func rcList(_ context.Context, s *Server, _ Params) (Params, error) {
	var out []Params
	names := make([]string, 0, len(calls))
	for n := range calls {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		c := calls[n]
		out = append(out, Params{"Path": n, "Help": c.help, "Available": s.has(c.needs)})
	}
	return Params{"commands": out}, nil
}

func coreVersion(context.Context, *Server, Params) (Params, error) {
	return Params{"version": Version, "os": runtime.GOOS, "arch": runtime.GOARCH, "goVersion": runtime.Version()}, nil
}

func coreCapabilities(_ context.Context, s *Server, _ Params) (Params, error) {
	out := Params{"library": s.FS != nil, "node": s.Node != nil, "version": Version}
	if s.FS != nil {
		out["member"] = s.FS.C.Member
	}
	return out, nil
}

type job struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime,omitzero"`
	Finished  bool      `json:"finished"`
	Success   bool      `json:"success"`
	Error     string    `json:"error"`
	Output    Params    `json:"output"`
	cancel    context.CancelFunc
}

func (s *Server) startJob(name string, c call, in Params) int64 {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if s.jobs == nil {
		s.jobs = map[int64]*job{}
	}
	s.jobSeq++
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{ID: s.jobSeq, Name: name, StartTime: time.Now(), cancel: cancel}
	s.jobs[j.ID] = j
	go func() {
		out, err := c.fn(ctx, s, in)
		s.jobsMu.Lock()
		defer s.jobsMu.Unlock()
		j.Finished, j.EndTime, j.Output, j.Success = true, time.Now(), out, err == nil
		if err != nil {
			j.Error = err.Error()
		}
		cancel()
	}()
	return j.ID
}

func jobID(in Params) (int64, error) {
	switch v := in["jobid"].(type) {
	case float64:
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	}
	return 0, fmt.Errorf("%w: jobid is required", errBadParam)
}

func jobList(_ context.Context, s *Server, _ Params) (Params, error) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	ids := []int64{}
	for id := range s.jobs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return Params{"jobids": ids}, nil
}

func jobStatus(_ context.Context, s *Server, in Params) (Params, error) {
	id, err := jobID(in)
	if err != nil {
		return nil, err
	}
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	j := s.jobs[id]
	if j == nil {
		return nil, fmt.Errorf("job %d: %w", id, os.ErrNotExist)
	}
	p, err := toParams(j)
	if err == nil {
		end := j.EndTime
		if end.IsZero() {
			end = time.Now()
		}
		p["duration"] = end.Sub(j.StartTime).Seconds()
	}
	return p, err
}

func jobStop(_ context.Context, s *Server, in Params) (Params, error) {
	id, err := jobID(in)
	if err != nil {
		return nil, err
	}
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if j := s.jobs[id]; j != nil {
		j.cancel()
		return Params{}, nil
	}
	return nil, fmt.Errorf("job %d: %w", id, os.ErrNotExist)
}

// --- operations, pool -------------------------------------------------------

func opList(ctx context.Context, s *Server, in Params) (Params, error) {
	remote, _ := str(in, "remote", false)
	recurse := false
	if opt, ok := in["opt"].(map[string]any); ok {
		recurse, _ = opt["recurse"].(bool)
	}
	list, err := s.FS.List(ctx, remote, recurse)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []vfs.Entry{}
	}
	return Params{"list": list}, nil
}

func opStat(ctx context.Context, s *Server, in Params) (Params, error) {
	remote, err := str(in, "remote", true)
	if err != nil {
		return nil, err
	}
	e, err := s.FS.Stat(ctx, remote)
	if err != nil {
		return nil, err
	}
	return Params{"item": e}, nil
}

func opAbout(ctx context.Context, s *Server, _ Params) (Params, error) {
	a, _, err := s.FS.About(ctx)
	if err != nil {
		return nil, err
	}
	return toParams(a)
}

func opDeleteFile(ctx context.Context, s *Server, in Params) (Params, error) {
	remote, err := str(in, "remote", true)
	if err != nil {
		return nil, err
	}
	return Params{}, s.FS.Remove(ctx, remote)
}

func opPurge(ctx context.Context, s *Server, in Params) (Params, error) {
	remote, err := str(in, "remote", true)
	if err != nil {
		return nil, err
	}
	removed, skipped, err := s.FS.RemoveAll(ctx, remote, boolean(in, "dryRun"))
	return Params{"removed": orEmpty(removed), "notOwned": orEmpty(skipped)}, err
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func isPool(f string) bool { return f == "pool:" || strings.HasPrefix(f, "pool:") }

func opCopyFile(ctx context.Context, s *Server, in Params) (Params, error) {
	var p [4]string
	for i, k := range []string{"srcFs", "srcRemote", "dstFs", "dstRemote"} {
		v, err := str(in, k, true)
		if err != nil {
			return nil, err
		}
		p[i] = v
	}
	srcFs, srcRemote, dstFs, dstRemote := p[0], p[1], p[2], p[3]
	if isPool(srcFs) == isPool(dstFs) {
		return nil, fmt.Errorf("%w: exactly one side must be \"pool:\" (no server-side copy within the pool)", errBadParam)
	}
	if !s.AllowLocalFiles {
		return nil, fmt.Errorf("%w: local file access is disabled on this rc (enable auth and --rc-files)", os.ErrPermission)
	}
	if isPool(dstFs) {
		local := filepath.Join(srcFs, filepath.FromSlash(srcRemote))
		return Params{}, s.upload(ctx, local, path.Join(strings.TrimPrefix(dstFs, "pool:"), dstRemote))
	}
	local := filepath.Join(dstFs, filepath.FromSlash(dstRemote))
	return Params{}, s.download(ctx, path.Join(strings.TrimPrefix(srcFs, "pool:"), srcRemote), local)
}

func (s *Server) upload(ctx context.Context, local, remote string) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	t := s.Stats.Begin(remote, fi.Size())
	_, err = s.FS.Put(ctx, remote, t.Reader(f), fi.ModTime())
	t.Done(err)
	return err
}

func (s *Server) download(ctx context.Context, remote, local string) error {
	f, m, err := s.FS.Open(ctx, remote)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return err
	}
	tmp := local + ".mppart"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	t := s.Stats.Begin(remote, m.Size)
	_, err = io.Copy(out, t.Reader(f))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, local)
		if m.ModTime != 0 {
			mt := time.Unix(0, m.ModTime)
			_ = os.Chtimes(local, mt, mt)
		}
	} else {
		os.Remove(tmp)
	}
	t.Done(err)
	return err
}

// uploadFile streams each multipart part straight into the pool.
func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	dir := vfs.Clean(r.URL.Query().Get("remote"))
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, "operations/uploadfile", nil, http.StatusBadRequest, err)
		return
	}
	var done []string
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, "operations/uploadfile", nil, http.StatusBadRequest, err)
			return
		}
		name := path.Base(part.FileName())
		if part.FileName() == "" || name == "." || name == "/" {
			continue
		}
		remote := path.Join(dir, name)
		t := s.Stats.Begin(remote, -1)
		_, err = s.FS.Put(r.Context(), remote, t.Reader(part), time.Now())
		t.Done(err)
		if err != nil {
			writeErr(w, "operations/uploadfile", Params{"remote": remote}, http.StatusInternalServerError, err)
			return
		}
		done = append(done, remote)
	}
	writeJSON(w, Params{"uploaded": orEmpty(done)})
}

func poolStatus(ctx context.Context, s *Server, _ Params) (Params, error) {
	st, err := s.FS.C.Status(ctx)
	if err != nil {
		return nil, err
	}
	return toParams(st)
}

// serveFile streams a pool file with Range support: players can seek, and
// a media server can be pointed at /files/.
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request) {
	if s.FS == nil {
		http.Error(w, "no library on this rc", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/files")
	f, m, err := s.FS.Open(r.Context(), p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	defer f.Close()
	t := s.Stats.Begin(m.Path, m.Size)
	var mt time.Time
	if m.ModTime != 0 {
		mt = time.Unix(0, m.ModTime)
	}
	cw := &countingWriter{ResponseWriter: w, t: t}
	http.ServeContent(cw, r, path.Base(m.Path), mt, f)
	t.Done(nil)
}

type countingWriter struct {
	http.ResponseWriter
	t *stats.Transfer
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.t.Add(int64(n))
	return n, err
}

// --- node -------------------------------------------------------------------

func nodeStatus(_ context.Context, s *Server, _ Params) (Params, error) {
	addr, reach := s.Node.Addr()
	return toParams(Params{"id": s.Node.ID(), "addr": addr, "reach": reach, "bridge": s.Node.IsBridge(),
		"capacity": s.Node.Capacity(), "reachability": s.Node.Reach()})
}

func nodeLimitsSet(_ context.Context, s *Server, in Params) (Params, error) {
	c := s.Node.Capacity()
	quota, up, down, drain := c.Quota, c.UploadBps, c.DownloadBps, c.Drain
	if v, _ := str(in, "quota", false); v != "" {
		var b limits.Bytes
		if err := b.Set(v); err != nil {
			return nil, fmt.Errorf("%w: quota: %v", errBadParam, err)
		}
		quota = int64(b)
	}
	for k, dst := range map[string]*int64{"upload_limit": &up, "download_limit": &down} {
		if v, _ := str(in, k, false); v != "" {
			var r limits.Rate
			if err := r.Set(v); err != nil {
				return nil, fmt.Errorf("%w: %s: %v", errBadParam, k, err)
			}
			*dst = r.BytesPerSec()
		}
	}
	if _, ok := in["drain"]; ok {
		drain = boolean(in, "drain")
	}
	s.Node.SetLimits(quota, up, down, drain)
	return toParams(s.Node.Capacity())
}

// RandomPassword returns credentials for an rc started without any.
func RandomPassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
