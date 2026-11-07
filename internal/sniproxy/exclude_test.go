//go:build linux

package sniproxy

import (
	"net/netip"
	"testing"
)

func TestApplicableExcludes(t *testing.T) {
	p := &Proxy{}
	p.neigh.dump = func() (map[netip.Addr]string, error) {
		return map[netip.Addr]string{netip.MustParseAddr("192.168.50.9"): "aa:bb:cc:00:00:09"}, nil
	}
	pols := []Policy{
		{ID: 1, ExcludeMACs: map[string]bool{"aa:bb:cc:00:00:09": true}, ExcludeNets: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")}},
		{ID: 2},
	}
	p.pol.Store(&pols)
	ids := func(ip string) (out []int) {
		for _, pol := range p.applicable(netip.MustParseAddr(ip)) {
			out = append(out, pol.ID)
		}
		return out
	}
	for ip, want := range map[string]int{"192.168.50.9": 1, "10.8.0.4": 1, "192.168.50.10": 2} {
		if got := ids(ip); len(got) != want {
			t.Errorf("%s: policies %v", ip, got)
		}
	}
	if got := ids("192.168.50.9"); got[0] != 2 {
		t.Errorf("excluded MAC still gets policy 1: %v", got)
	}
}
