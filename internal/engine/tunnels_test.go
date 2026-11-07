package engine

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

const testOVPN = "client\nremote vpn.example.net 1194 udp\nauth-user-pass\n<ca>\nCERT\n</ca>\n"

func TestApplyRunsNeededTunnelsOnly(t *testing.T) {
	k := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	conf := "[Interface]\nPrivateKey = " + k(1) + "\nAddress = 10.64.1.2/32\n[Peer]\nPublicKey = " + k(2) + "\nEndpoint = vpn.example.net:51820\nAllowedIPs = 0.0.0.0/0\n"
	dir := t.TempDir()
	c := config.Default()
	c.Settings.PreResolve = false
	c.WireGuard = []config.WireGuard{
		{ID: "wgx1", Name: "Tokyo", Enabled: true, Conf: conf},
		{ID: "wgx2", Name: "saved", Enabled: true, Conf: conf},  // no policy uses it
		{ID: "wgx3", Name: "off", Enabled: false, Conf: conf},   // disabled, used by a policy
		{ID: "wgx4", Name: "unused", Enabled: true, Conf: conf}, // only in a disabled policy
	}
	c.OpenVPN = []config.OpenVPN{
		{ID: "ovx1", Name: "Paris", Enabled: true, Conf: testOVPN, Username: "u", Password: "p"},
		{ID: "ovx2", Name: "saved", Enabled: true, Conf: testOVPN, Username: "u", Password: "p"},
	}
	c.Policies = []config.Policy{
		{Name: "p", Enabled: true, Tunnels: []string{"wgx1", "ovx1", "wgx3", "wgc1"}, KillSwitch: true, Domains: []string{"example.com"}, Leak: config.Leak{IPv6: "off", WebRTC: "off"}},
		{Name: "q", Enabled: false, Tunnels: []string{"wgx4", "ovx2"}, Domains: []string{"example.org"}, Leak: config.Leak{IPv6: "off", WebRTC: "off"}},
	}
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{
		Responses: map[string]string{"ip -o link show": "5: wgx2: <POINTOPOINT,UP> mtu 1420\n"},
		Fail:      map[string]bool{"ip link show dev": true},
	}
	e := New(DefaultPaths(dir), rec)
	e.ovpn.Dir = filepath.Join(dir, "ovpn")
	e.ovpn.Alive = func(int, string) bool { return false }
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(usedTunnels(e.runtime()), ","); got != "ovx1,wgc1,wgx1,wgx3" {
		t.Fatalf("used tunnels %s", got)
	}
	if err := e.Apply("test"); err != nil {
		t.Fatal(err)
	}
	out := rec.Joined()
	for _, s := range []string{"ip link add dev wgx1 type wireguard", "ip link del dev wgx2",
		"openvpn --config " + filepath.Join(dir, "ovpn", "ovx1.conf") + " --daemon snake-ovx1",
		"ip -4 rule add pref 5401 fwmark 0xf40000/0xc0ff0000 lookup 1311",   // wgx1 probe
		"ip -4 rule add pref 5421 fwmark 0xe00000/0xc0ff0000 lookup 1331"} { // ovx1 probe
		if !strings.Contains(out, s) {
			t.Errorf("missing %q", s)
		}
	}
	for _, s := range []string{"dev wgx3 type", "dev wgx4 type", "ovx2"} {
		if strings.Contains(out, s) {
			t.Errorf("started %q although no enabled policy needs it", s)
		}
	}
	// The interface exists before routes point at it.
	if strings.Index(out, "ip link add dev wgx1") > strings.Index(out, "route replace") {
		t.Error("routes before the interface")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "ovpn", "ovx1.auth")); err != nil || string(b) != "u\np\n" {
		t.Fatalf("credentials %q %v", b, err)
	}

	// The policy stops using ovx1: its client is stopped and its files go.
	c2 := e.Config()
	c2.Policies[0].Tunnels = []string{"wgx1"}
	if err := e.SetConfig(c2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ovpn", "ovx1.auth")); !os.IsNotExist(err) {
		t.Fatal("credentials of a stopped client left behind")
	}
}
