// Package reach works out how other members can reach this node: its public
// IP (STUN), a port mapping on the home router (UPnP IGD or NAT-PMP), and
// whether it's behind carrier-grade NAT, where neither helps and the node
// has to fall back to a relay. Which candidate address actually works is
// decided by the coordinator dialing it back, never by guessing here.
package reach

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// DefaultSTUN are public STUN servers queried in order.
var DefaultSTUN = []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}

const stunCookie = 0x2112A442

// PublicIP asks a STUN server (RFC 5389 binding request) which address our
// UDP packets come from. Behind a home router that's the router's public
// address; behind CGNAT it's the carrier's, which nobody can dial into.
func PublicIP(ctx context.Context, server string) (net.IP, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001) // binding request
	binary.BigEndian.PutUint32(req[4:], stunCookie)
	txid := req[8:20]
	if _, err := rand.Read(txid); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseBindingResponse(buf[:n], txid)
}

func parseBindingResponse(b, txid []byte) (net.IP, error) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0101 ||
		binary.BigEndian.Uint32(b[4:]) != stunCookie || string(b[8:20]) != string(txid) {
		return nil, errors.New("stun: not a binding success response for our request")
	}
	attrs := b[20:min(len(b), 20+int(binary.BigEndian.Uint16(b[2:])))]
	var mapped net.IP
	for len(attrs) >= 4 {
		typ, l := binary.BigEndian.Uint16(attrs[0:]), int(binary.BigEndian.Uint16(attrs[2:]))
		if len(attrs) < 4+l {
			break
		}
		v := attrs[4 : 4+l]
		switch {
		case typ == 0x0020 && l >= 8 && v[1] == 0x01: // XOR-MAPPED-ADDRESS, IPv4
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(v[4:])^stunCookie)
			return ip, nil
		case typ == 0x0001 && l >= 8 && v[1] == 0x01: // MAPPED-ADDRESS, IPv4
			mapped = net.IP(append([]byte(nil), v[4:8]...))
		}
		attrs = attrs[4+(l+3)&^3:]
	}
	if mapped != nil {
		return mapped, nil
	}
	return nil, fmt.Errorf("stun: no IPv4 mapped address in response")
}

var cgnat = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// NonPublic reports whether ip can't be dialed from the internet: private,
// loopback, link-local or carrier-grade NAT space.
func NonPublic(ip net.IP) bool {
	return ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}
