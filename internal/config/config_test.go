package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func load(t *testing.T) *Config {
	t.Helper()
	b, err := os.ReadFile("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		t.Fatal(err)
	}
	c.ApplyDefaults()
	c.Normalize()
	return c
}

func TestNormalizeAndValidate(t *testing.T) {
	c := load(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	p := c.Policies[0]
	if p.ID != 1 || c.Policies[1].ID != 2 || c.Policies[2].ID != 3 {
		t.Fatalf("ids not assigned: %d %d %d", p.ID, c.Policies[1].ID, c.Policies[2].ID)
	}
	want := []string{"# Netflix", "netflix.com", "**.nflxvideo.net", "nflximg.net", `/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/`, "~nflxso", "!=customerevents.netflix.com"}
	if strings.Join(p.Domains, ",") != strings.Join(want, ",") {
		t.Fatalf("domains = %v", p.Domains)
	}
	if p.ExpectedCountry != "US" {
		t.Fatalf("country = %q", p.ExpectedCountry)
	}
	if got := c.ResolveDevices(c.Policies[1]); len(got) != 2 || got[0] != "aa:bb:cc:00:00:01" {
		t.Fatalf("group expansion = %v", got)
	}
	if c.Policies[1].Scope() != "devices+destinations" || c.Policies[2].Scope() != "whole-device" || p.Scope() != "destinations" {
		t.Fatal("scope detection wrong")
	}
}

func TestValidateErrors(t *testing.T) {
	c := load(t)
	c.Policies[0].Tunnels = []string{"wgc9"}
	c.Policies[1].Devices = []string{"group:nope"}
	c.Policies[2].Leak.IPv6 = "maybe"
	c.Policies[1].Domains = append(c.Policies[1].Domains, "/bad(regex/")
	c.Policies = append(c.Policies, Policy{Name: "empty", ID: 4, Tunnels: []string{"wgc1"}, Leak: Leak{IPv6: "off", WebRTC: "off"}})
	err := c.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, s := range []string{"unknown tunnel", "unknown group", "ipv6 mode", "needs at least one", "bad regex"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("missing %q in %v", s, err)
		}
	}
}

func TestMarks(t *testing.T) {
	s := DefaultSettings()
	if s.MarkShift() != 22 || s.MaxMarkValue() != 0xff {
		t.Fatalf("shift %d max %x", s.MarkShift(), s.MaxMarkValue())
	}
	if s.PolicyMark(3) != 0xc00000 {
		t.Fatalf("mark %x", s.PolicyMark(3))
	}
	seen := map[uint32]bool{}
	for id := 1; id <= s.MaxPolicyID(); id++ {
		seen[s.PolicyMark(id)] = true
	}
	for _, tn := range TunnelNames {
		m := s.ProbeMark(tn)
		if seen[m] || m&^s.MarkMask != 0 || m == 0 {
			t.Fatalf("probe mark %x for %s collides or escapes mask", m, tn)
		}
		seen[m] = true
	}
	if TunnelInterface("ovpnc3") != "tun13" || TunnelInterface("wgc2") != "wgc2" {
		t.Fatal("interface mapping")
	}
}

func TestParseASN(t *testing.T) {
	for in, want := range map[string]int{"AS2906": 2906, "as40027": 40027, " 13335 ": 13335} {
		if got, err := ParseASN(in); err != nil || got != want {
			t.Errorf("ParseASN(%q) = %d, %v", in, got, err)
		}
	}
	if _, err := ParseASN("ASX"); err == nil {
		t.Error("expected error")
	}
}

func TestRuleListsExpand(t *testing.T) {
	c := Default()
	c.RuleLists = []RuleList{
		{Name: "nf", Domains: []string{"netflix.com", "!=ads.netflix.com"}, ASNs: []int{2906}, CIDRs: []string{"23.246.0.0/18"}},
		{Name: "dis", Domains: []string{"disneyplus.com", "netflix.com"}},
	}
	c.Policies = []Policy{
		{Name: "only lists", Enabled: true, Tunnels: []string{"wgc1"}, Lists: []string{"nf", "dis"}, Leak: Leak{IPv6: "off", WebRTC: "off"}},
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatalf("a policy whose rules all come from lists is valid: %v", err)
	}
	rt := c.Runtime()
	p := rt.Policies[0]
	if strings.Join(p.Domains, ",") != "netflix.com,!=ads.netflix.com,disneyplus.com" || len(p.ASNs) != 1 || len(p.CIDRs) != 1 || p.Lists != nil {
		t.Fatalf("expanded = %+v", p)
	}
	if len(c.Policies[0].Domains) != 0 {
		t.Fatal("Runtime must not modify the stored config")
	}
	c.Policies[0].Lists = []string{"missing"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "unknown rule list") {
		t.Fatalf("err = %v", err)
	}
	c.Policies[0].Lists = nil
	c.RuleLists = append(c.RuleLists, RuleList{Name: "nf", Domains: []string{"bad domain"}})
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate rule list") || !strings.Contains(err.Error(), "invalid domain") {
		t.Fatalf("err = %v", err)
	}
}

func TestSTUNServerTTL(t *testing.T) {
	c := Default()
	c.ApplyDefaults()
	if c.Settings.STUNServerTTL != 86400 {
		t.Fatalf("default ttl %d", c.Settings.STUNServerTTL)
	}
	c.Settings.STUNServerTTL = 3000000
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "stun_server_ttl") {
		t.Fatalf("over ipset max accepted: %v", err)
	}
}

func TestDropRulesDoNotChangeScope(t *testing.T) {
	p := Policy{Devices: []string{"aa:bb:cc:00:00:01"}, Domains: []string{"# c", "drop:ads.example.com", "drop:asn:1234"}}
	if p.HasDomains() || !p.HasDrops() || p.HasDestinations() || p.Scope() != "whole-device" {
		t.Fatalf("domains=%v drops=%v dest=%v scope=%s", p.HasDomains(), p.HasDrops(), p.HasDestinations(), p.Scope())
	}
	c := Default()
	c.Policies = []Policy{{Name: "blocklist", Enabled: true, Tunnels: []string{"wgc1"}, Domains: []string{"DROP:Ads.Example.com", "drop:cidr:10.1.2.3"}, Leak: Leak{IPv6: "off", WebRTC: "off"}}}
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatalf("drop-only policy rejected: %v", err)
	}
	if c.Policies[0].Domains[0] != "drop:ads.example.com" {
		t.Fatalf("normalized %v", c.Policies[0].Domains)
	}
	c.Policies[0].Domains = append(c.Policies[0].Domains, "!drop:x.example")
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("!drop: accepted: %v", err)
	}
}

func TestEncryptedDNSConfig(t *testing.T) {
	c := Default()
	c.Policies = []Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, Domains: []string{"example.com"},
		Leak: Leak{DNSViaTunnel: true, DNSServer: "1.1.1.1", DNSProtocol: "DoH", IPv6: "off", WebRTC: "off"}}}
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	l := c.Policies[0].Leak
	if l.DNSProtocol != DNSDoH || l.DNSTLSName != "cloudflare-dns.com" || l.DNSDoHPath != "/dns-query" || !l.Encrypted() {
		t.Fatalf("defaults not filled: %+v", l)
	}
	c.Policies[0].Leak = Leak{DNSViaTunnel: true, DNSServer: "203.0.113.5", DNSProtocol: DNSDoT, IPv6: "off", WebRTC: "off"}
	c.Normalize()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "dns_tls_name") {
		t.Fatalf("unknown resolver without a name should fail: %v", err)
	}
	c.Policies[0].Leak.DNSProtocol = "quic"
	if err := c.Validate(); err == nil {
		t.Fatal("bad protocol accepted")
	}
	c.Policies[0].Leak.DNSProtocol = DNSUDP
	c.Settings.BlockDoT = "sometimes"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "block_dot") {
		t.Fatalf("bad block_dot accepted: %v", err)
	}
}

func TestMigrateMarkMask(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/config.json"
	if err := os.WriteFile(p, []byte(`{"version":1,"settings":{"mark_mask":16711680}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Settings.MarkMask != DefaultMarkMask || c.MigratedMarkMask() != LegacyMarkMask || c.Version != CurrentVersion {
		t.Fatalf("not migrated: mask %#x migrated %#x version %d", c.Settings.MarkMask, c.MigratedMarkMask(), c.Version)
	}
	if c.Settings.MarkMask&AdaptiveQoSMask != 0 || c.Settings.MarkMask&0xf000 != 0 {
		t.Fatal("default mask overlaps Adaptive QoS or VPN Director")
	}
	// A custom mask, or the old mask chosen again in a current config, is kept.
	for _, js := range []string{`{"version":1,"settings":{"mark_mask":65280}}`, `{"version":2,"settings":{"mark_mask":16711680}}`} {
		_ = os.WriteFile(p, []byte(js), 0o644)
		c, _ := Load(p)
		if c.MigratedMarkMask() != 0 || (c.Settings.MarkMask != 0xff00 && c.Settings.MarkMask != LegacyMarkMask) {
			t.Fatalf("%s: mask %#x migrated %#x", js, c.Settings.MarkMask, c.MigratedMarkMask())
		}
	}
}
