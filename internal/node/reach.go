package node

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"mediapool/internal/proto"
	"mediapool/internal/reach"
	"mediapool/internal/relay"
	"mediapool/internal/transfer"
)

// ReachOptions controls how the node makes itself reachable.
type ReachOptions struct {
	// Mode: "auto" tries direct addresses and falls back to the relay;
	// "direct" never relays; "relay" always relays; "off" advertises
	// Config.Addr unchecked (local setups and tests).
	Mode string
	// ListenPort is the TCP port the node's HTTP server listens on.
	ListenPort int
	// Announce is an address the operator configured (port forward, DNS
	// name, reverse proxy). It's tried first.
	Announce string
	// PortMap tries UPnP/NAT-PMP on the router.
	PortMap bool
	// RelayURL is the relay to use when nothing direct works.
	RelayURL string
	STUN     []string
	Recheck  time.Duration
}

// ReachReport is what the last reachability check found.
type ReachReport struct {
	Mode       string            `json:"mode"`
	Addr       string            `json:"addr"`
	Reach      string            `json:"reach"`
	PublicIP   string            `json:"public_ip,omitempty"`
	RouterIP   string            `json:"router_ip,omitempty"`
	CGNAT      bool              `json:"cgnat"`
	PortMap    string            `json:"port_map,omitempty"`
	Tried      []string          `json:"tried"`
	Errors     map[string]string `json:"errors,omitempty"`
	RelayUp    bool              `json:"relay_up"`
	CheckedAt  time.Time         `json:"checked_at"`
	Suggestion string            `json:"suggestion,omitempty"`
}

type reachState struct {
	mu      sync.Mutex
	report  ReachReport
	mapping *reach.Mapping
	cancel  context.CancelFunc // stops the relay tunnel
}

func (n *Node) Reach() ReachReport {
	n.rs.mu.Lock()
	defer n.rs.mu.Unlock()
	return n.rs.report
}

// RunReachability establishes reachability, then re-checks periodically
// until ctx is done. It blocks; run it in a goroutine.
func (n *Node) RunReachability(ctx context.Context, o ReachOptions) {
	if o.Mode == "" {
		o.Mode = "auto"
	}
	if o.Recheck == 0 {
		o.Recheck = 30 * time.Minute
	}
	if len(o.STUN) == 0 {
		o.STUN = reach.DefaultSTUN
	}
	defer func() {
		n.rs.mu.Lock()
		if n.rs.mapping != nil {
			n.rs.mapping.Close()
		}
		if n.rs.cancel != nil {
			n.rs.cancel()
		}
		n.rs.mu.Unlock()
	}()
	for {
		n.checkReach(ctx, o)
		select {
		case <-ctx.Done():
			return
		case <-time.After(o.Recheck):
		}
	}
}

func (n *Node) checkReach(ctx context.Context, o ReachOptions) {
	rep := ReachReport{Mode: o.Mode, Errors: map[string]string{}, CheckedAt: time.Now()}
	if o.Mode == "off" {
		addr, _ := n.Addr()
		rep.Addr, rep.Reach = addr, ""
		n.setReport(rep)
		return
	}

	var cands []string
	kind := map[string]string{}
	add := func(u, k string) {
		if u != "" && kind[u] == "" {
			cands, kind[u] = append(cands, u), k
		}
	}
	if o.Mode != "relay" {
		add(o.Announce, "direct")
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		for _, s := range o.STUN {
			if ip, err := reach.PublicIP(ctx, s); err == nil {
				rep.PublicIP = ip.String()
				break
			} else {
				rep.Errors["stun "+s] = err.Error()
			}
		}
		if o.PortMap {
			n.rs.mu.Lock()
			m := n.rs.mapping
			n.rs.mu.Unlock()
			var err error
			if m != nil {
				err = m.Renew()
			} else if m, err = reach.MapPort(ctx, o.ListenPort); err == nil {
				n.rs.mu.Lock()
				n.rs.mapping = m
				n.rs.mu.Unlock()
			}
			if err != nil {
				rep.Errors["port mapping"] = err.Error()
			} else {
				rep.PortMap = fmt.Sprintf("%s %s:%d", m.Method, m.ExternalIP, m.ExternalPort)
				rep.RouterIP = m.ExternalIP.String()
				if reach.NonPublic(m.ExternalIP) {
					rep.CGNAT = true // the router itself sits behind another NAT
				} else {
					add("http://"+net.JoinHostPort(m.ExternalIP.String(), strconv.Itoa(m.ExternalPort)), "mapped")
				}
			}
		}
		cancel()
		if rep.PublicIP != "" {
			if rep.RouterIP != "" && rep.RouterIP != rep.PublicIP {
				rep.CGNAT = true
			}
			add("http://"+net.JoinHostPort(rep.PublicIP, strconv.Itoa(o.ListenPort)), "direct")
		}
	}
	rep.Tried = cands

	var reachable []string
	if len(cands) > 0 {
		var pr proto.ProbeResponse
		err := transfer.PostJSON(ctx, n.cfg.HTTP, n.id, n.coordBase()+"/v1/probe", proto.ProbeRequest{Candidates: cands}, &pr)
		if err != nil {
			rep.Errors["probe"] = err.Error()
		} else {
			reachable = pr.Reachable
			for k, v := range pr.Errors {
				rep.Errors[k] = v
			}
		}
	}

	if len(reachable) > 0 {
		rep.Addr, rep.Reach = reachable[0], kind[reachable[0]]
		n.stopRelay()
		n.SetAddr(rep.Addr, rep.Reach)
		n.setReport(rep)
		n.cfg.Logf("reachable directly at %s (%s)", rep.Addr, rep.Reach)
		return
	}
	if o.Mode == "direct" || o.RelayURL == "" {
		rep.Suggestion = suggestion(rep, o)
		addr, _ := n.Addr()
		rep.Addr = addr
		n.setReport(rep)
		n.cfg.Logf("not reachable from the internet. %s", rep.Suggestion)
		return
	}
	rep.Addr, rep.Reach = relay.AddrFor(o.RelayURL, n.cfg.ID), "relay"
	if o.Mode == "auto" {
		rep.Suggestion = suggestion(rep, o)
	}
	n.SetAddr(rep.Addr, rep.Reach)
	n.startRelay(ctx, o.RelayURL)
	n.setReport(rep)
	n.cfg.Logf("using relay %s (%s)", o.RelayURL, rep.Suggestion)
}

func suggestion(rep ReachReport, o ReachOptions) string {
	switch {
	case o.Mode == "relay":
		return "relay forced by configuration"
	case rep.CGNAT:
		return "your ISP puts you behind carrier-grade NAT, so port forwarding can't work; ask your ISP for a public IPv4 address, or keep using the relay"
	case rep.PortMap == "" && o.PortMap:
		return fmt.Sprintf("forward TCP port %d on your router to this machine (automatic UPnP/NAT-PMP mapping failed), or set MP_ANNOUNCE to an address that reaches it", o.ListenPort)
	default:
		return fmt.Sprintf("check that TCP port %d is forwarded and not blocked by a firewall", o.ListenPort)
	}
}

func (n *Node) setReport(rep ReachReport) {
	n.rs.mu.Lock()
	rep.RelayUp = n.rs.report.RelayUp && rep.Reach == "relay"
	n.rs.report = rep
	n.rs.mu.Unlock()
}

func (n *Node) startRelay(ctx context.Context, relayURL string) {
	n.rs.mu.Lock()
	defer n.rs.mu.Unlock()
	if n.rs.cancel != nil {
		return // already tunnelled
	}
	rctx, cancel := context.WithCancel(ctx)
	n.rs.cancel = cancel
	go relay.Serve(rctx, relayURL, n.id, n.Handler(), func(up bool) {
		n.rs.mu.Lock()
		n.rs.report.RelayUp = up
		n.rs.mu.Unlock()
	}, n.cfg.Logf)
}

func (n *Node) stopRelay() {
	n.rs.mu.Lock()
	defer n.rs.mu.Unlock()
	if n.rs.cancel != nil {
		n.rs.cancel()
		n.rs.cancel = nil
	}
}

// PortOf extracts the port from a listen address like ":7100".
func PortOf(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(p)
	return port
}
