package engine

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/health"
	"github.com/irisariuan/snake/internal/system"
	"golang.org/x/net/dns/dnsmessage"
)

func lookupEngine(t *testing.T) (*Engine, *system.Recorder) {
	t.Helper()
	rec := &system.Recorder{Responses: map[string]string{
		"nvram get wan0_ipaddr":     "198.51.100.20",
		"ip route get 9.9.9.9 mark": "9.9.9.9 dev wgc1 table 111 src 10.64.1.2 mark 0x1 uid 0\n    cache\n",
		"ip route get 1.1.1.1":      "1.1.1.1 via 198.51.100.1 dev eth0 src 198.51.100.20 uid 0\n    cache\n",
		"ip route get 127.0.0.1":    "local 127.0.0.1 dev lo src 127.0.0.1 uid 0\n    cache\n",
	}}
	e := New(DefaultPaths(t.TempDir()), rec)
	c := config.Default()
	c.Policies = []config.Policy{{ID: 1, Name: "Streaming", Enabled: true, Tunnels: []string{"wgc1"}, Domains: []string{"netflix.com"},
		Leak: config.Leak{DNSViaTunnel: true, DNSServer: "9.9.9.9", DNSProtocol: config.DNSUDP}}}
	e.cfg, e.rt = c, c.Runtime()
	e.mon = health.NewMonitor(rec)
	e.mon.Set(health.Status{Tunnel: "wgc1", Healthy: true, ExitIP: "203.0.113.5", Country: "JP"})
	return e, rec
}

func hops(r []Hop) string {
	var s []string
	for _, h := range r {
		s = append(s, h.What+" | "+h.Detail)
	}
	return strings.Join(s, "\n")
}

func TestRouterRoute(t *testing.T) {
	e, _ := lookupEngine(t)
	old := resolvDnsmasq
	resolvDnsmasq = filepath.Join(t.TempDir(), "resolv.dnsmasq")
	defer func() { resolvDnsmasq = old }()
	_ = os.WriteFile(resolvDnsmasq, []byte("server=/lan/192.168.1.1\nserver=1.1.1.1\nserver=8.8.8.8\n"), 0o600)

	e.active = map[int]string{1: "wgc1"}
	got := hops(e.routerRoute(e.runtime(), "www.netflix.com"))
	for _, want := range []string{"Policy Streaming resolves netflix.com", "tunnel wgc1", "Out interface wgc1 (tunnel wgc1)", "table 111", "203.0.113.5 JP", "Resolver 9.9.9.9:53"} {
		if !strings.Contains(got, want) {
			t.Errorf("policy route lacks %q:\n%s", want, got)
		}
	}
	e.active = map[int]string{}
	if got := hops(e.routerRoute(e.runtime(), "netflix.com")); !strings.Contains(got, "No healthy tunnel") || strings.Contains(got, "Resolver") {
		t.Errorf("route without a tunnel:\n%s", got)
	}
	got = hops(e.routerRoute(e.runtime(), "example.org"))
	for _, want := range []string{"The router's WAN DNS: 1.1.1.1, 8.8.8.8", "Out interface eth0 (WAN, the ISP sees this query)", "gateway 198.51.100.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("WAN route lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "192.168.1.1") {
		t.Errorf("domain-specific server listed as upstream:\n%s", got)
	}
	if w := e.wanDNS(); len(w.Servers) != 2 || w.Servers[0] != "1.1.1.1" || w.DoT {
		t.Errorf("WAN DNS: %+v", w)
	}
}

func TestWANDNSSetting(t *testing.T) {
	e, rec := lookupEngine(t)
	old := resolvDnsmasq
	resolvDnsmasq = filepath.Join(t.TempDir(), "missing")
	defer func() { resolvDnsmasq = old }()
	rec.Responses["nvram get wan0_dns"] = "203.0.113.53 203.0.113.54\n"
	if w := e.wanDNS(); len(w.Servers) != 2 || w.Servers[0] != "203.0.113.53" || w.Source != "nvram wan0_dns" {
		t.Fatalf("ISP DNS: %+v", w)
	}
	// Merlin's DNS-over-TLS: dnsmasq asks Stubby, which asks over TLS.
	rec.Responses["nvram get dnspriv_enable"] = "1"
	rec.Responses["nvram get dnspriv_rulelist"] = "<1.1.1.1>>cloudflare-dns.com><9.9.9.9>853>dns.quad9.net>"
	w := e.wanDNS()
	if !w.DoT || w.Servers[0] != "127.0.1.1" || len(w.DoTServers) != 2 || w.DoTServers[0] != "1.1.1.1 (cloudflare-dns.com)" || w.DoTServers[1] != "9.9.9.9:853 (dns.quad9.net)" {
		t.Fatalf("DoT: %+v", w)
	}
	got := hops(e.routerRoute(e.runtime(), "example.org"))
	for _, want := range []string{"Stubby on 127.0.1.1", "Sent over TLS to 1.1.1.1 (cloudflare-dns.com)", "Out interface eth0"} {
		if !strings.Contains(got, want) {
			t.Errorf("DoT route lacks %q:\n%s", want, got)
		}
	}
	// The WAN path with no resolver given follows the same setting.
	r := e.DNSLookup("example.org", "A", "wan", "")
	if r.Server != "127.0.1.1:53" || !strings.Contains(hops(r.Route), "Stubby") {
		t.Fatalf("WAN path ignores the router's DNS setting: %s\n%s", r.Server, hops(r.Route))
	}
	if r.Error != "" && r.TookMs <= 0 {
		t.Fatalf("failed lookup has no time: %+v", r.Result)
	}
	// A resolver typed in is asked as given.
	if r := e.DNSLookup("example.org", "A", "wan", "127.0.0.9:5353"); r.Server != "127.0.0.9:5353" {
		t.Fatalf("typed resolver: %s", r.Server)
	}
}

func TestDNSLookupPaths(t *testing.T) {
	e, rec := lookupEngine(t)
	if r := e.DNSLookup("example.org", "A", "wgc9", ""); !strings.Contains(r.Error, "unknown path") {
		t.Fatalf("unknown tunnel: %+v", r)
	}
	if r := e.DNSLookup("example.org", "A", "wan", "dns.google"); !strings.Contains(r.Error, "IP address") {
		t.Fatalf("resolver by name: %+v", r)
	}
	if r := e.DNSLookup(" ", "A", "", ""); r.Error == "" {
		t.Fatal("empty name accepted")
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 1500)
		n, a, err := pc.ReadFrom(b)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		_ = q.Unpack(b[:n])
		h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 9}
		out, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions,
			Answers: []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}}).Pack()
		_, _ = pc.WriteTo(out, a)
	}()
	r := e.DNSLookup("example.org", "A", "wan", pc.LocalAddr().String())
	if r.Error != "" || len(r.Records) != 1 || r.Records[0].Data != "192.0.2.1" || r.Via != "wan" {
		t.Fatalf("lookup: %+v", r)
	}
	if got := hops(r.Route); !strings.Contains(got, "Out interface lo") || !strings.Contains(got, "Resolver "+pc.LocalAddr().String()) {
		t.Fatalf("route:\n%s", got)
	}
	if !strings.Contains(rec.Joined(), "ip route get 127.0.0.1") {
		t.Fatal("kernel route not asked")
	}
}
