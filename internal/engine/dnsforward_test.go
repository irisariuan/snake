package engine

import (
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/netfilter"
)

func TestPolicyDNSUpstreams(t *testing.T) {
	c := config.Default()
	var states []netfilter.PolicyState
	for i, proto := range []string{config.DNSUDP, config.DNSUDP, config.DNSDoT, config.DNSDoH, config.DNSDoT} {
		states = append(states, netfilter.PolicyState{Policy: config.Policy{
			ID: i + 1, Name: "dns", Enabled: true, Domains: []string{"test.example"},
			Leak: config.Leak{DNSViaTunnel: true, DNSServer: "9.9.9.9", DNSProtocol: proto},
		}, ActiveTunnel: "wgc1"})
	}
	states[1].ActiveTunnel = "ovpnc2"
	states[2].ActiveTunnel = "wgc2"
	states[4].ActiveTunnel = ""
	up := dnsUpstreams(states, map[int]string{3: "127.0.0.1#34567", 5: "127.0.0.1#34568"})
	if up[1] != "9.9.9.9@wgc1" || up[2] != "9.9.9.9@tun12" || up[3] != "127.0.0.1#34567" || up[4] != "" || up[5] != "127.0.0.1#34568" {
		t.Fatalf("upstreams: %v", up)
	}
	specs := forwarders(c, states)
	if len(specs) != 3 || specs[0].Up.Mark != c.Settings.ProbeMark("wgc2") || !specs[2].Up.Disabled || specs[2].Up.Mark != 0 {
		t.Fatalf("forwarders: %+v", specs)
	}
	for _, sp := range specs {
		if sp.Up.Proto == config.DNSUDP {
			t.Fatal("plain DNS unexpectedly uses a local listener")
		}
	}
	states[0].ActiveTunnel = ""
	if dnsUpstreams(states, nil)[1] != "" {
		t.Fatal("down plain-DNS policy fell back to WAN")
	}
	states[2].ActiveTunnel = "ovpnc3"
	if got := forwarders(c, states)[0].Up.Mark; got != c.Settings.ProbeMark("ovpnc3") {
		t.Fatalf("failover did not update DNS socket mark: %#x", got)
	}
	if !strings.Contains(up[3], "#34567") {
		t.Fatal("runtime listener port was lost")
	}
}
