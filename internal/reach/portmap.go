package reach

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
)

const leaseTime = time.Hour

// Mapping is a port forward the router agreed to. Keep it alive with Renew
// before the lease runs out, and Close it on shutdown.
type Mapping struct {
	Method       string // "upnp" or "natpmp"
	ExternalIP   net.IP // the router's WAN address
	ExternalPort int
	renew        func() error
	close        func() error
}

func (m *Mapping) Renew() error { return m.renew() }
func (m *Mapping) Close() error { return m.close() }

func localIP() (net.IP, error) {
	c, err := net.Dial("udp", "192.0.2.1:9") // no packets are sent
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP, nil
}

// MapPort asks the home router to forward external TCP port `port` to this
// machine, trying UPnP IGD first (most consumer routers) and NAT-PMP second
// (Apple and some others). It fails when the router supports neither, has
// them disabled, or this process can't see the router (e.g. a container on
// a bridge network: use host networking for automatic mapping).
func MapPort(ctx context.Context, port int) (*Mapping, error) {
	upnpErr := error(nil)
	if m, err := mapUPnP(ctx, port); err == nil {
		return m, nil
	} else {
		upnpErr = err
	}
	if m, err := mapNATPMP(port); err == nil {
		return m, nil
	} else {
		return nil, fmt.Errorf("no port mapping: upnp: %v; nat-pmp: %v", upnpErr, err)
	}
}

func mapUPnP(ctx context.Context, port int) (*Mapping, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ip, err := localIP()
	if err != nil {
		return nil, err
	}
	type igd interface {
		AddPortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string, intPort uint16, intClient string, enabled bool, desc string, lease uint32) error
		DeletePortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string) error
		GetExternalIPAddressCtx(ctx context.Context) (string, error)
	}
	var clients []igd
	if cs, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			clients = append(clients, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			clients = append(clients, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			clients = append(clients, c)
		}
	}
	if len(clients) == 0 {
		return nil, errors.New("no UPnP gateway found")
	}
	var lastErr error
	for _, c := range clients {
		add := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return c.AddPortMappingCtx(ctx, "", uint16(port), "TCP", uint16(port), ip.String(), true, "mediapool", uint32(leaseTime/time.Second))
		}
		if err := add(); err != nil {
			lastErr = err
			continue
		}
		extStr, _ := c.GetExternalIPAddressCtx(ctx)
		return &Mapping{
			Method: "upnp", ExternalIP: net.ParseIP(extStr), ExternalPort: port, renew: add,
			close: func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return c.DeletePortMappingCtx(ctx, "", uint16(port), "TCP")
			},
		}, nil
	}
	return nil, lastErr
}

func mapNATPMP(port int) (*Mapping, error) {
	gw, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}
	c := natpmp.NewClientWithTimeout(gw, 3*time.Second)
	ext, err := c.GetExternalAddress()
	if err != nil {
		return nil, err
	}
	m := &Mapping{Method: "natpmp", ExternalIP: net.IP(ext.ExternalIPAddress[:])}
	add := func() error {
		r, err := c.AddPortMapping("tcp", port, port, int(leaseTime/time.Second))
		if err == nil {
			m.ExternalPort = int(r.MappedExternalPort)
		}
		return err
	}
	if err := add(); err != nil {
		return nil, err
	}
	m.renew = add
	m.close = func() error { _, err := c.AddPortMapping("tcp", port, 0, 0); return err }
	return m, nil
}
