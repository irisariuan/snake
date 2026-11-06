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
	if s.MarkShift() != 16 || s.MaxMarkValue() != 0xff {
		t.Fatalf("shift %d max %x", s.MarkShift(), s.MaxMarkValue())
	}
	if s.PolicyMark(3) != 0x30000 {
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
