package engine

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

func TestApplyRunsWireGuard(t *testing.T) {
	k := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	conf := "[Interface]\nPrivateKey = " + k(1) + "\nAddress = 10.64.1.2/32\n[Peer]\nPublicKey = " + k(2) + "\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0\n"
	dir := t.TempDir()
	c := config.Default()
	c.Settings.PreResolve = false
	c.WireGuard = []config.WireGuard{
		{ID: "wgx1", Name: "Tokyo", Enabled: true, Conf: conf},
		{ID: "wgx2", Name: "spare", Enabled: true, Conf: conf},
		{ID: "wgx3", Name: "off", Enabled: false, Conf: conf},
	}
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgx1", "wgc1"}, KillSwitch: true,
		Domains: []string{"example.com"}, Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{
		Responses: map[string]string{"ip -o link show": "5: wgx3: <POINTOPOINT,UP> mtu 1420\n"},
		Fail:      map[string]bool{"ip link show dev": true},
	}
	e := New(DefaultPaths(dir), rec)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	// Monitored: the policy's tunnels and every enabled snake tunnel.
	if got := strings.Join(usedTunnels(e.runtime()), ","); got != "wgc1,wgx1,wgx2" {
		t.Fatalf("used tunnels %s", got)
	}
	if err := e.Apply("test"); err != nil {
		t.Fatal(err)
	}
	out := rec.Joined()
	for _, s := range []string{"ip link add dev wgx1 type wireguard", "ip link add dev wgx2 type wireguard", "ip link del dev wgx3",
		"ip -4 rule add pref 5401 fwmark 0xf40000/0xc0ff0000 lookup 1311"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q", s)
		}
	}
	// The interface exists before routes point at it.
	if strings.Index(out, "ip link add dev wgx1") > strings.Index(out, "route replace") {
		t.Error("routes before the interface")
	}
}
