package fwvpn

import (
	"errors"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/openvpn"
	"github.com/irisariuan/snake/internal/wireguard"
)

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func files(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if s, ok := m[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("no such file")
	}
}

func TestReadWireGuard(t *testing.T) {
	kv := ParseNVRAM(strings.Join([]string{
		"wgc1_enable=1", "wgc1_desc=Tokyo #1", "wgc1_priv=" + key, "wgc1_addr=10.2.0.2/32", "wgc1_mtu=1412",
		"wgc1_ppub=" + key, "wgc1_psk=" + key, "wgc1_aips=0.0.0.0/0,::/0", "wgc1_ep_addr=vpn.example.net", "wgc1_ep_port=51821", "wgc1_alive=30",
		"wgc2_enable=0", "wgc2_priv=", "wgc2_ep_addr=", "wgc2_aips=0.0.0.0/0", // empty slot
		"wgc3_priv=" + key, "wgc3_ep_addr=2001:db8::1", // no peer key
	}, "\n"))
	got := Read(kv, files(nil))
	if len(got) != 2 || got[0].ID != "wgc1" || got[1].ID != "wgc3" {
		t.Fatalf("clients: %+v", got)
	}
	c := got[0]
	if c.Error != "" || !c.Enabled || c.Name != "Tokyo #1" || c.Server != "vpn.example.net:51821" {
		t.Fatalf("wgc1: %+v", c)
	}
	conf, err := wireguard.Parse(c.Conf)
	if err != nil {
		t.Fatal(err)
	}
	p := conf.Peers[0]
	if conf.MTU != 1412 || len(conf.Addresses) != 1 || p.Endpoint != "vpn.example.net:51821" || p.PresharedKey != key || p.Keepalive != 30 || len(p.AllowedIPs) != 2 {
		t.Fatalf("conf: %+v", conf)
	}
	if got[1].Error == "" || got[1].Server != "[2001:db8::1]:51820" {
		t.Fatalf("wgc3 should be unusable: %+v", got[1])
	}
}

func TestReadOpenVPN(t *testing.T) {
	kv := ParseNVRAM("vpn_client1_addr=ovpn.example.net\nvpn_client1_port=1194\nvpn_client1_desc=Work\nvpn_clientx_eas=1,\n" +
		"vpn_client2_addr=other.example.net\nvpn_client3_addr=\n")
	fs := files(map[string]string{
		"/etc/openvpn/client1/config.ovpn": "# Automatically generated configuration\ndaemon ovpn-client1\nclient\ndev tun11\nproto udp4\nremote ovpn.example.net 1194\n" +
			"ca ca.crt\ncert client.crt\nkey client.key\ntls-auth static.key 1\nauth-user-pass up\nstatus status 5\nup updown-client.sh\nverb 3\n",
		"/etc/openvpn/client1/ca.crt":     "CA\n",
		"/etc/openvpn/client1/client.crt": "CERT\n",
		"/etc/openvpn/client1/client.key": "KEY\n",
		"/etc/openvpn/client1/static.key": "STATIC\n",
		"/etc/openvpn/client1/up":         "alice\ns3cret\n",
	})
	got := Read(kv, fs)
	if len(got) != 2 {
		t.Fatalf("clients: %+v", got)
	}
	c := got[0]
	if c.ID != "ovpnc1" || c.Error != "" || !c.Enabled || c.Username != "alice" || c.Password != "s3cret" || c.Server != "ovpn.example.net 1194" {
		t.Fatalf("ovpnc1: %+v", c)
	}
	pc, err := openvpn.Parse(c.Conf)
	if err != nil || !pc.NeedsAuth {
		t.Fatalf("parse: %v %+v", err, pc)
	}
	run := pc.Render("ovx1", "/tmp/creds", "/tmp/pid")
	for _, want := range []string{"<ca>\nCA\n</ca>", "<tls-auth>\nSTATIC\n</tls-auth>", "key-direction 1", "<key>\nKEY\n</key>"} {
		if !strings.Contains(run, want) {
			t.Errorf("rendered configuration lacks %q:\n%s", want, run)
		}
	}
	for _, not := range []string{"daemon ovpn-client1", "dev tun11", "updown-client.sh", "status status"} {
		if strings.Contains(run, not) {
			t.Errorf("rendered configuration keeps %q", not)
		}
	}
	// Set up but never started: nothing to copy yet.
	if got[1].ID != "ovpnc2" || !strings.Contains(got[1].Error, "start the client once") {
		t.Fatalf("ovpnc2: %+v", got[1])
	}
}
