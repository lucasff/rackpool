package relay

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mediapool/internal/auth"
)

// The tunnel works over TLS (wss://), as it does behind Cloudflare Tunnel or
// any HTTPS reverse proxy, and forwards requests with the signed URI intact.
func TestTunnelOverTLS(t *testing.T) {
	key := auth.Generate()
	pool := &auth.Pool{Nodes: []auth.NodeEntry{{ID: "n1", Key: auth.PubHex(key), Owner: "o"}}, Members: []auth.Member{{Name: "o", Key: auth.PubHex(auth.Generate())}}}
	rs := &Server{Pool: pool}
	srv := httptest.NewTLSServer(rs)
	defer srv.Close()

	// The test server's certificate is self-signed: trust it for this test.
	old := http.DefaultClient
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = old }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	up := make(chan bool, 4)
	node := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s|%s", r.URL.Path, r.Header.Get(OriginalURIHeader))
	})
	go Serve(ctx, srv.URL, auth.NewIdentity(key), node, func(b bool) { up <- b }, t.Logf)
	select {
	case ok := <-up:
		if !ok {
			t.Fatal("tunnel didn't come up")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out connecting over TLS")
	}

	resp, err := srv.Client().Get(AddrFor(srv.URL, "n1") + "/v1/ping?nonce=x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "/v1/ping|/relay/n1/v1/ping?nonce=x" {
		t.Fatalf("forwarded as %q", b)
	}

	// Strangers can't register a tunnel.
	go Serve(ctx, srv.URL, auth.NewIdentity(auth.Generate()), node, func(b bool) {
		if b {
			t.Error("unknown key got a tunnel")
		}
	}, func(string, ...any) {})
	time.Sleep(300 * time.Millisecond)
	if len(rs.Connected()) != 1 {
		t.Fatalf("connected: %v", rs.Connected())
	}
}
