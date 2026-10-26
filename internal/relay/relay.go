// Package relay makes nodes behind carrier-grade NAT reachable. Such a node
// can't accept connections, so it dials out to a relay and keeps a
// WebSocket open; the relay serves /relay/<node-id>/... on its behalf and
// forwards each request down that connection (multiplexed with yamux). A
// WebSocket passes through reverse proxies and Cloudflare Tunnel, so the
// relay can sit behind one.
//
// A relay is trusted for availability only. Shards are ciphertext verified
// against Merkle roots, requests to nodes are signed end to end, and upload
// tickets are coordinator-signed, so a relay can drop or delay traffic but
// can't read, forge or alter it. It does carry the bytes, so it's rate
// limited and placement treats relayed nodes as low-bandwidth.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"mediapool/internal/auth"
	"mediapool/internal/limits"
)

const (
	upgradeProto = "mediapool-relay/1"
	// OriginalURIHeader carries the URI the client signed, so the node can
	// verify a request whose path the relay shortened.
	OriginalURIHeader = "X-Mp-Original-Uri"
	connectPath       = "/v1/relay/connect"
)

// Server is the relay side. Mount it at both "/v1/relay/" and "/relay/".
type Server struct {
	Pool *auth.Pool
	// PerNodeBps caps how fast traffic for one node flows through the relay
	// (bytes/s, each direction; 0 = unlimited).
	PerNodeBps int64
	Logf       func(format string, args ...any)

	verify auth.Verifier
	mu     sync.Mutex
	nodes  map[string]*tunnel
}

type tunnel struct {
	sess  *yamux.Session
	proxy *httputil.ReverseProxy
}

func (s *Server) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	}
}

// Connected lists the node IDs currently tunnelled through this relay.
func (s *Server) Connected() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.nodes))
	for id := range s.nodes {
		out = append(out, id)
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == connectPath {
		s.handleConnect(w, r)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/relay/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	id, path, _ := strings.Cut(rest, "/")
	s.mu.Lock()
	t := s.nodes[id]
	s.mu.Unlock()
	if t == nil {
		http.Error(w, "node not connected to this relay", http.StatusBadGateway)
		return
	}
	r2 := r.Clone(r.Context())
	r2.Header.Set(OriginalURIHeader, r.URL.RequestURI())
	r2.URL.Path, r2.URL.RawPath = "/"+path, ""
	t.proxy.ServeHTTP(w, r2)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	pub, err := s.verify.Verify(r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	p, ok := s.Pool.Lookup(pub)
	if !ok || p.Node == nil {
		http.Error(w, "only pool nodes can use the relay", http.StatusForbidden)
		return
	}
	// A real WebSocket, so the tunnel passes through proxies and CDNs that
	// only forward WebSocket upgrades (Cloudflare Tunnel among them).
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{upgradeProto},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	ws.SetReadLimit(-1)
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	sess, err := yamux.Client(conn, yamuxConfig())
	if err != nil {
		conn.Close()
		return
	}
	id := p.Node.ID
	up, down := limits.NewBucket(s.PerNodeBps), limits.NewBucket(s.PerNodeBps)
	t := &tunnel{sess: sess}
	t.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", id, id
			pr.Out.Header.Set(OriginalURIHeader, pr.In.Header.Get(OriginalURIHeader))
		},
		Transport: &limits.Transport{
			Up: up, Down: down,
			Base: &http.Transport{
				DialContext:         func(context.Context, string, string) (net.Conn, error) { return sess.Open() },
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     time.Minute,
			},
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "relay: "+err.Error(), http.StatusBadGateway)
		},
	}
	s.mu.Lock()
	if s.nodes == nil {
		s.nodes = map[string]*tunnel{}
	}
	old := s.nodes[id]
	s.nodes[id] = t
	s.mu.Unlock()
	if old != nil {
		old.sess.Close() // the node reconnected; drop the stale tunnel
	}
	s.logf("relay: node %s connected from %s", id, r.RemoteAddr)
	<-sess.CloseChan()
	s.mu.Lock()
	if s.nodes[id] == t {
		delete(s.nodes, id)
	}
	s.mu.Unlock()
	s.logf("relay: node %s disconnected", id)
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.KeepAliveInterval = 20 * time.Second
	c.MaxStreamWindowSize = 4 << 20
	return c
}

// AddrFor returns the URL other members use to reach nodeID through the
// relay at relayURL.
func AddrFor(relayURL, nodeID string) string {
	return strings.TrimRight(relayURL, "/") + "/relay/" + nodeID
}

// Serve connects to the relay and serves h over the tunnel until ctx is
// done, reconnecting with backoff. connected is called each time the tunnel
// comes up (with true) or drops (with false).
func Serve(ctx context.Context, relayURL string, id *auth.Identity, h http.Handler, connected func(bool), logf func(string, ...any)) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := serveOnce(ctx, relayURL, id, h, connected)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		logf("relay %s: %v; reconnecting in %v", relayURL, err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func serveOnce(ctx context.Context, relayURL string, id *auth.Identity, h http.Handler, connected func(bool)) error {
	u, err := url.Parse(strings.TrimRight(relayURL, "/") + connectPath)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return fmt.Errorf("relay URL must be http:// or https://, got %q", relayURL)
	}
	// Sign the request as the relay will see it: GET on the connect path.
	signed, _ := http.NewRequest(http.MethodGet, strings.TrimRight(relayURL, "/")+connectPath, nil)
	id.Sign(signed, nil)
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ws, resp, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{
		HTTPHeader:      http.Header{"Authorization": signed.Header.Values("Authorization")},
		Subprotocols:    []string{upgradeProto},
		CompressionMode: websocket.CompressionDisabled,
	})
	cancel()
	if err != nil {
		if resp != nil {
			return fmt.Errorf("relay refused: %s", resp.Status)
		}
		return err
	}
	ws.SetReadLimit(-1)
	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	sess, err := yamux.Server(conn, yamuxConfig())
	if err != nil {
		conn.Close()
		return err
	}
	connected(true)
	defer connected(false)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second}
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()
	err = srv.Serve(sess)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, io.EOF) {
		err = errors.New("tunnel closed")
	}
	return err
}
