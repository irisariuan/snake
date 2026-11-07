package wireguard

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/system"
)

func key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func sample() string {
	return "# Mullvad Tokyo\n[Interface]\nPrivateKey = " + key(1) + "\nAddress = 10.64.1.2/32, fc00:bbbb::2/128\nDNS = 10.64.0.1\nPostUp = iptables -I ...\nTable = off\n\n" +
		"[Peer]\nPublicKey = " + key(2) + "\nPresharedKey = " + key(3) + "\nEndpoint = jp-tyo.example.net:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
}

func TestParse(t *testing.T) {
	c, err := Parse(strings.ReplaceAll(sample(), "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Addresses) != 2 || c.Addresses[0].String() != "10.64.1.2/32" || c.Mtu() != DefaultMTU || len(c.Peers) != 1 || c.Peers[0].Keepalive != 25 {
		t.Fatalf("parsed %+v", c)
	}
	sc := c.Setconf()
	for _, s := range []string{"PrivateKey = " + key(1), "PresharedKey = " + key(3), "Endpoint = jp-tyo.example.net:51820", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"} {
		if !strings.Contains(sc, s) {
			t.Errorf("setconf missing %q:\n%s", s, sc)
		}
	}
	// wg setconf rejects wg-quick's keys.
	for _, s := range []string{"Address", "DNS", "PostUp", "Table"} {
		if strings.Contains(sc, s) {
			t.Errorf("setconf has %s:\n%s", s, sc)
		}
	}
}

func TestDefaultKeepalive(t *testing.T) {
	c, err := Parse(strings.Replace(sample(), "PersistentKeepalive = 25", "PersistentKeepalive = off", 1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Setconf(), "PersistentKeepalive = 25") {
		t.Fatalf("no keepalive:\n%s", c.Setconf())
	}
}

func TestParseErrors(t *testing.T) {
	ok := sample()
	for want, text := range map[string]string{
		"PrivateKey":       strings.Replace(ok, "PrivateKey = "+key(1), "", 1),
		"not a WireGuard":  strings.Replace(ok, key(2), "short", 1),
		"needs an Address": strings.Replace(ok, "Address = 10.64.1.2/32, fc00:bbbb::2/128", "", 1),
		"Endpoint":         strings.Replace(ok, "jp-tyo.example.net:51820", "jp-tyo.example.net", 1),
		"needs a [Peer]":   ok[:strings.Index(ok, "[Peer]")],
		"unknown [Peer]":   ok + "Foo = 1\n",
		"MTU":              strings.Replace(ok, "DNS =", "MTU = 100\nDNS =", 1),
		"":                 "",
	} {
		_, err := Parse(text)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want error with %q, got %v", want, err)
		}
	}
}

func TestSync(t *testing.T) {
	c, err := Parse(sample())
	if err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{
		Responses: map[string]string{
			"ip -o link show": "1: lo: <LOOPBACK,UP> mtu 65536\n7: wgc1: <POINTOPOINT,UP> mtu 1420\n9: wgx3: <POINTOPOINT> mtu 1420\n",
			"ip -o addr show dev wgx1": "8: wgx1    inet 10.9.9.9/32 scope global wgx1\\       valid_lft forever\n" +
				"8: wgx1    inet6 fe80::1/64 scope link\\       valid_lft forever\n",
		},
		Fail: map[string]bool{"ip link show dev wgx1": true},
	}
	m := &Manager{R: rec, Owned: func(n string) bool { return strings.HasPrefix(n, "wgx") }}
	if err := m.Sync([]Tunnel{{Name: "wgx1", Conf: c}}); err != nil {
		t.Fatal(err)
	}
	out := rec.Joined()
	for _, s := range []string{
		"ip link add dev wgx1 type wireguard",
		"wg setconf wgx1 /dev/stdin <<EOF\n[Interface]\nPrivateKey = " + key(1),
		"ip addr add 10.64.1.2/32 dev wgx1",
		"ip addr add fc00:bbbb::2/128 dev wgx1",
		"ip addr del 10.9.9.9/32 dev wgx1",
		"ip link set dev wgx1 mtu 1420 up",
		"ip link del dev wgx3", // no longer configured
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	for _, s := range []string{"fe80::1", "del dev wgc1", "wg syncconf"} {
		if strings.Contains(out, s) {
			t.Errorf("unexpected %q in\n%s", s, out)
		}
	}

	// Unchanged: no reconfiguration (it would interrupt the session).
	rec.Commands, rec.Fail = nil, nil
	if err := m.Sync([]Tunnel{{Name: "wgx1", Conf: c}}); err != nil {
		t.Fatal(err)
	}
	if out := rec.Joined(); strings.Contains(out, "wg ") || strings.Contains(out, "link add") {
		t.Errorf("reconfigured unchanged tunnel:\n%s", out)
	}
	// Changed peer: syncconf, which keeps the session when possible.
	c.Peers[0].Endpoint = "jp-osa.example.net:51820"
	rec.Commands = nil
	if err := m.Sync([]Tunnel{{Name: "wgx1", Conf: c}}); err != nil {
		t.Fatal(err)
	}
	if out := rec.Joined(); !strings.Contains(out, "wg syncconf wgx1 /dev/stdin") || strings.Contains(out, "wg setconf") {
		t.Errorf("expected syncconf only:\n%s", out)
	}
}

func TestSyncReportsMissingWireGuard(t *testing.T) {
	c, _ := Parse(sample())
	rec := &system.Recorder{Fail: map[string]bool{"ip link show dev": true, "ip link add": true}}
	m := &Manager{R: rec}
	err := m.Sync([]Tunnel{{Name: "wgx1", Conf: c}})
	if err == nil || !strings.Contains(err.Error(), "does this firmware have WireGuard") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(rec.Joined(), "modprobe wireguard") {
		t.Error("module not loaded on demand")
	}
}

func TestRedact(t *testing.T) {
	c, _ := Parse(sample())
	if s := redact(errString("bad line PrivateKey = "+key(1)), c); strings.Contains(s, key(1)) {
		t.Fatal(s)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
