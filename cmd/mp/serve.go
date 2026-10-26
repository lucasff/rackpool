package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"mediapool/internal/rc"
	"mediapool/internal/serve"
	"mediapool/internal/vfs"
)

func basicAuth(user, pass string, h http.Handler) http.Handler {
	if user == "" {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="mediapool"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkExposure refuses to serve a non-loopback address without credentials
// unless the operator explicitly opts in.
func checkExposure(addr, user string, noAuth bool) error {
	if user == "" && !noAuth && !isLoopback(addr) {
		return fmt.Errorf("refusing to serve %s without --user/--pass (or pass --no-auth if that's really intended)", addr)
	}
	return nil
}

func listen(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 30 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "serve", Short: "Serve the pool over HTTP or WebDAV"}
	var addr, user, pass string
	var noAuth, readOnly bool
	flags := func(c *cobra.Command, def string) {
		c.Flags().StringVar(&addr, "addr", def, "listen address")
		c.Flags().StringVar(&user, "user", "", "require this basic-auth user")
		c.Flags().StringVar(&pass, "pass", "", "basic-auth password")
		c.Flags().BoolVar(&noAuth, "no-auth", false, "allow serving a non-loopback address without credentials")
	}
	httpCmd := &cobra.Command{
		Use:   "http",
		Short: "Browse and stream the pool over HTTP (range requests: players can seek)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkExposure(addr, user, noAuth); err != nil {
				return err
			}
			v, err := openFS()
			if err != nil {
				return err
			}
			log.Printf("serving pool over HTTP on %s", addr)
			return listen(cmd.Context(), addr, basicAuth(user, pass, httpHandler(v)))
		},
	}
	flags(httpCmd, "127.0.0.1:8080")
	davCmd := &cobra.Command{
		Use:   "webdav",
		Short: "Serve the pool over WebDAV (Infuse, Kodi, VLC, Finder, Explorer)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkExposure(addr, user, noAuth); err != nil {
				return err
			}
			v, err := openFS()
			if err != nil {
				return err
			}
			log.Printf("serving pool over WebDAV on %s (read-only=%v)", addr, readOnly)
			return listen(cmd.Context(), addr, basicAuth(user, pass, serve.WebDAV(v, readOnly, log.Printf)))
		},
	}
	flags(davCmd, "127.0.0.1:8081")
	davCmd.Flags().BoolVar(&readOnly, "read-only", false, "refuse uploads and deletes")
	cmd.AddCommand(httpCmd, davCmd)
	return cmd
}

func httpHandler(v *vfs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e, err := v.Stat(r.Context(), r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if !e.IsDir {
			f, m, err := v.Open(r.Context(), e.Path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer f.Close()
			t := st.Begin(m.Path, m.Size)
			http.ServeContent(w, r, path.Base(m.Path), e.ModTime, f)
			t.Done(nil)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return
		}
		list, err := v.List(r.Context(), e.Path, false)
		if err != nil && e.Path != "/" {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>%s</title><h1>%s</h1><pre>\n", html.EscapeString(e.Path), html.EscapeString(e.Path))
		if e.Path != "/" {
			fmt.Fprintln(w, `<a href="../">../</a>`)
		}
		for _, x := range list {
			name := x.Name
			if x.IsDir {
				name += "/"
			}
			fmt.Fprintf(w, "<a href=\"%s\">%s</a>%s %10s\n", (&url.URL{Path: name}).String(), html.EscapeString(name),
				strings.Repeat(" ", max(1, 60-len(name))), human(x.Size))
		}
		fmt.Fprintln(w, "</pre>")
	})
}

func rcdCmd() *cobra.Command {
	var addr, user, pass string
	var noAuth, noGUI, files bool
	cmd := &cobra.Command{
		Use:   "rcd",
		Short: "Run the remote-control daemon and web UI",
		Long:  "Serves the rc API (POST /<group>/<method>, see `mp rc rc/list`), /files/<path> for streaming,\nand the web UI at / . Bound to localhost by default.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkExposure(addr, user, noAuth); err != nil {
				return err
			}
			v, err := openFS()
			if err != nil {
				return err
			}
			s := &rc.Server{FS: v, Stats: st, User: user, Pass: pass, WebGUI: !noGUI, AllowLocalFiles: files && user != ""}
			if files && user == "" {
				log.Printf("--rc-files ignored: local file access needs --rc-user/--rc-pass")
			}
			log.Printf("rc on http://%s (web UI: %v)", addr, !noGUI)
			return listen(cmd.Context(), addr, s.Handler())
		},
	}
	cmd.Flags().StringVar(&addr, "rc-addr", "127.0.0.1:5572", "listen address")
	cmd.Flags().StringVar(&user, "rc-user", "", "require this basic-auth user")
	cmd.Flags().StringVar(&pass, "rc-pass", "", "basic-auth password")
	cmd.Flags().BoolVar(&noAuth, "rc-no-auth", false, "allow a non-loopback address without credentials")
	cmd.Flags().BoolVar(&noGUI, "rc-no-web-gui", false, "don't serve the web UI")
	cmd.Flags().BoolVar(&files, "rc-files", false, "let operations/copyfile read and write this machine's files (needs auth)")
	return cmd
}

func rcCmd() *cobra.Command {
	var rcURL, user, pass, jsonIn string
	cmd := &cobra.Command{
		Use:   "rc <group/method> [key=value ...]",
		Short: "Call a running rcd or mp-node",
		Example: "  mp rc rc/list\n  mp rc operations/list remote=/movies\n  mp rc node/limits/set upload_limit=50M\n" +
			"  mp rc operations/copyfile --json '{\"srcFs\":\"/media\",\"srcRemote\":\"a.mkv\",\"dstFs\":\"pool:\",\"dstRemote\":\"/movies/a.mkv\",\"_async\":true}'",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in := map[string]any{}
			if jsonIn != "" {
				if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
					return fmt.Errorf("--json: %w", err)
				}
			}
			for _, kv := range args[1:] {
				k, val, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("argument %q isn't key=value", kv)
				}
				in[k] = val
			}
			body, _ := json.Marshal(in)
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, strings.TrimRight(rcURL, "/")+"/"+strings.Trim(args[0], "/"), bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			if user != "" {
				req.SetBasicAuth(user, pass)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			out, _ := io.ReadAll(resp.Body)
			os.Stdout.Write(out)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s", resp.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&rcURL, "url", "http://127.0.0.1:5572", "rc address")
	cmd.Flags().StringVar(&user, "rc-user", "", "basic-auth user")
	cmd.Flags().StringVar(&pass, "rc-pass", "", "basic-auth password")
	cmd.Flags().StringVar(&jsonIn, "json", "", "parameters as a JSON object")
	return cmd
}
