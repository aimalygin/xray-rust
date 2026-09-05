// Run in the exact Xray-core module with scripts/check-routing-oracle.sh.
// Both this oracle and the Rust tests consume the same synthetic cases.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
)

type fixtureTarget struct {
	Address    string
	Port       uint16
	Network    string
	InboundTag string
}

type fixtureCase struct {
	Name            string
	Routing         conf.RouterConfig
	Target          fixtureTarget
	Answers         []string
	DNSFailure      bool
	SkipDNSResolve  bool
	ExpectedTag     string
	ExpectedLookups int
}

type fixture struct {
	SchemaVersion  int
	XrayCoreCommit string
	Cases          []fixtureCase
}

type routeContext struct {
	routing.Context
	input fixtureTarget
	skip  bool
}

func (c routeContext) GetInboundTag() string   { return c.input.InboundTag }
func (c routeContext) GetTargetPort() net.Port { return net.Port(c.input.Port) }
func (c routeContext) GetSkipDNSResolve() bool { return c.skip }
func (c routeContext) GetNetwork() net.Network {
	if c.input.Network == "udp" {
		return net.Network_UDP
	}
	if c.input.Network != "tcp" {
		panic("unknown fixture network")
	}
	return net.Network_TCP
}
func (c routeContext) GetTargetDomain() string {
	if net.ParseIP(c.input.Address) != nil {
		return ""
	}
	return c.input.Address
}
func (c routeContext) GetTargetIPs() []net.IP {
	if ip := net.ParseIP(c.input.Address); ip != nil {
		return []net.IP{ip}
	}
	return nil
}

type fakeDNS struct {
	dns.Client
	input fixtureCase
	calls int
}

func (d *fakeDNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	if domain != d.input.Target.Address || !option.IPv4Enable || !option.IPv6Enable || option.FakeEnable {
		panic("unexpected routing DNS query")
	}
	d.calls++
	if d.input.DNSFailure {
		return nil, 0, dns.ErrEmptyResponse
	}
	var ips []net.IP
	for _, answer := range d.input.Answers {
		ip := net.ParseIP(answer)
		if ip == nil {
			panic("invalid fixture address")
		}
		ips = append(ips, ip)
	}
	return ips, 60, nil
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: routing-oracle fixture.json")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var f fixture
	if err = json.Unmarshal(raw, &f); err != nil {
		return err
	}
	if f.SchemaVersion != 1 || f.XrayCoreCommit != "5ca6f4b7d4dc20a881d4330e498892697627ec0c" || len(f.Cases) == 0 {
		return fmt.Errorf("invalid fixture provenance or empty cases")
	}
	for _, c := range f.Cases {
		config, err := c.Routing.Build()
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		d := &fakeDNS{input: c}
		r := new(router.Router)
		if err = r.Init(context.Background(), config, d, nil, nil); err != nil {
			return err
		}
		ctx := routeContext{input: c.Target, skip: c.SkipDNSResolve}
		route, err := r.PickRoute(ctx)
		selected := "default"
		if err == nil {
			selected = route.GetOutboundTag()
		} else if err != common.ErrNoClue {
			return err
		}
		if err := r.Close(); err != nil {
			return err
		}
		if selected != c.ExpectedTag || d.calls != c.ExpectedLookups {
			return fmt.Errorf("%s: got tag=%s lookups=%d; want tag=%s lookups=%d", c.Name, selected, d.calls, c.ExpectedTag, c.ExpectedLookups)
		}
	}
	fmt.Printf("verified %d routing cases against Xray-core %s\n", len(f.Cases), f.XrayCoreCommit)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
