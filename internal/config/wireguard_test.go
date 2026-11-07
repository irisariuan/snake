package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func wgConf() string {
	k := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	return "[Interface]\nPrivateKey = " + k(1) + "\nAddress = 10.64.1.2/32\n[Peer]\nPublicKey = " + k(2) + "\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0\n"
}

func TestWireGuardSlots(t *testing.T) {
	s := DefaultSettings()
	// Firmware clients keep their indexes and probe marks.
	if TunnelIndex("wgc1") != 1 || TunnelIndex("ovpnc5") != 10 || s.ProbeMark("wgc1") != 0xf60000 || s.ProbeMark("ovpnc5") != 0xff0000 {
		t.Fatalf("firmware slots moved: %d %d %#x %#x", TunnelIndex("wgc1"), TunnelIndex("ovpnc5"), s.ProbeMark("wgc1"), s.ProbeMark("ovpnc5"))
	}
	for _, bad := range []string{"wgx0", "wgx21", "wgx01", "wgx", "wgxa"} {
		if TunnelIndex(bad) != 0 {
			t.Errorf("%s accepted", bad)
		}
	}
	seen := map[uint32]bool{}
	for id := 1; id <= s.MaxPolicyID(); id++ {
		seen[s.PolicyMark(id)] = true
	}
	all := append([]string(nil), TunnelNames...)
	for n := 1; n <= MaxWireGuard; n++ {
		all = append(all, WireGuardName(n))
	}
	idx := map[int]bool{}
	for _, tn := range all {
		m := s.ProbeMark(tn)
		if seen[m] || m&^s.MarkMask != 0 || m == 0 {
			t.Fatalf("probe mark %#x for %s collides or escapes mask", m, tn)
		}
		seen[m] = true
		i := TunnelIndex(tn)
		if i < 1 || i > MaxTunnels || idx[i] {
			t.Fatalf("index %d for %s", i, tn)
		}
		idx[i] = true
	}
	if !IsWireGuard("wgx20") || !IsWireGuard("wgc3") || IsWireGuard("ovpnc1") || TunnelInterface("wgx7") != "wgx7" {
		t.Fatal("wireguard naming")
	}
}

func TestWireGuardConfig(t *testing.T) {
	c := load(t)
	c.WireGuard = []WireGuard{{ID: "wgx2", Name: "Osaka", Enabled: true, Conf: wgConf()}, {Name: " Tokyo ", Enabled: true, Conf: strings.ReplaceAll(wgConf(), "\n", "\r\n")}}
	c.Policies[0].Tunnels = []string{"WGX1", "wgx2", "wgc1"}
	c.Normalize()
	if c.WireGuard[1].ID != "wgx1" || c.WireGuard[1].Name != "Tokyo" || strings.Contains(c.WireGuard[1].Conf, "\r") {
		t.Fatalf("normalize: %+v", c.WireGuard[1])
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.TunnelLabel("wgx1") != "wgx1 (Tokyo)" || c.TunnelLabel("wgc1") != "wgc1" {
		t.Fatal("labels")
	}

	c.Policies[0].Tunnels = []string{"wgx3"}
	c.WireGuard = append(c.WireGuard, WireGuard{ID: "wgx2", Conf: "[Interface]\n"}, WireGuard{ID: "wgx99", Conf: wgConf()})
	err := c.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, s := range []string{`tunnel "wgx3" is not set up`, `duplicate wireguard tunnel "wgx2"`, "needs a PrivateKey", `"wgx99" invalid`} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("missing %q in %v", s, err)
		}
	}
}

func TestWireGuardSlotLimit(t *testing.T) {
	c := Default()
	for i := 0; i <= MaxWireGuard; i++ {
		c.WireGuard = append(c.WireGuard, WireGuard{Conf: wgConf()})
	}
	c.Normalize()
	if c.WireGuard[MaxWireGuard-1].ID != WireGuardName(MaxWireGuard) || c.WireGuard[MaxWireGuard].ID != "" {
		t.Fatal("slots")
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "at most 20 WireGuard tunnels") {
		t.Fatalf("err = %v", err)
	}
}

func TestWireGuardNeedsMarkBits(t *testing.T) {
	c := Default()
	c.Settings.MarkMask = 0x003f0000 // 6 bits: no room below the probe marks
	c.Settings.ConnMarkMask = DefaultConnMarkMask
	c.WireGuard = []WireGuard{{ID: "wgx1", Enabled: true, Conf: wgConf()}}
	c.Normalize()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "too few bits") {
		t.Fatalf("err = %v", err)
	}
}
