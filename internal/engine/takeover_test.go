package engine

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

func TestTakeOver(t *testing.T) {
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	dir := t.TempDir()
	c := config.Default()
	leak := config.Leak{IPv6: "off", WebRTC: "off"}
	c.Policies = []config.Policy{
		{Name: "tv", Enabled: true, Tunnels: []string{"wgc1", "ovpnc1"}, Domains: []string{"example.tv"}, Leak: leak},
		{Name: "work", Enabled: true, Tunnels: []string{"wgc2"}, Domains: []string{"example.org"}, Leak: leak},
	}
	c.WireGuard = []config.WireGuard{{ID: "wgx1", Name: "mine", Enabled: true,
		Conf: "[Interface]\nPrivateKey = " + key + "\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = " + key + "\nEndpoint = 192.0.2.9:51820\nAllowedIPs = 0.0.0.0/0\n"}}
	c.Settings.PreResolve = false
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	nv := strings.Join([]string{
		"wgc1_enable=1", "wgc1_desc=Tokyo", "wgc1_priv=" + key, "wgc1_addr=10.2.0.2/32", "wgc1_ppub=" + key, "wgc1_aips=0.0.0.0/0", "wgc1_ep_addr=192.0.2.1", "wgc1_ep_port=51820",
		"vpn_client1_addr=192.0.2.2", "vpn_client1_port=1194", "vpn_clientx_eas=1,2,", "vpn_client1_enable=1",
	}, "\n")
	rec := &system.Recorder{Responses: map[string]string{"nvram show": nv}}
	old := takeOverReadFile
	defer func() { takeOverReadFile = old }()
	takeOverReadFile = func(p string) ([]byte, error) {
		if p == "/etc/openvpn/client1/config.ovpn" {
			return []byte("client\ndev tun11\nremote 192.0.2.2 1194\nca ca.crt\n"), nil
		}
		if p == "/etc/openvpn/client1/ca.crt" {
			return []byte("CA"), nil
		}
		return nil, errors.New("no such file")
	}
	e := New(DefaultPaths(dir), rec)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}

	pre, err := e.TakeOverPreview()
	if err != nil || pre.Applied || len(pre.Clients) != 2 || strings.Join(pre.Clients[0].UsedBy, ",") != "tv" {
		t.Fatalf("preview: %+v %v", pre, err)
	}
	if countCmds(rec, "service") != 0 || countCmds(rec, "nvram set") != 0 {
		t.Fatalf("preview changed the firmware: %v", rec.Commands)
	}
	if _, err := e.TakeOverClients([]string{"wgc2"}); err == nil {
		t.Fatal("wgc2 is not set up: want an error")
	}

	res, err := e.TakeOverClients(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || len(res.Clients) != 2 || res.Clients[0].Into != "wgx2" || res.Clients[1].Into != "ovx1" {
		t.Fatalf("result: %+v", res)
	}
	got := e.Config()
	if strings.Join(got.Policies[0].Tunnels, ",") != "wgx2,ovx1" || strings.Join(got.Policies[1].Tunnels, ",") != "wgc2" {
		t.Fatalf("policies: %v %v", got.Policies[0].Tunnels, got.Policies[1].Tunnels)
	}
	w, ok := got.WireGuardTunnel("wgx2")
	if !ok || w.Name != "wgc1 Tokyo" || !strings.Contains(w.Conf, "Endpoint = 192.0.2.1:51820") {
		t.Fatalf("wgx2: %+v", w)
	}
	if o, ok := got.OpenVPNTunnel("ovx1"); !ok || !strings.Contains(o.Conf, "<ca>\nCA\n</ca>") {
		t.Fatalf("ovx1: %+v", o)
	}
	all := rec.Joined()
	for _, want := range []string{"nvram set wgc1_enable=0", "service stop_wgc 1", "service stop_vpnclient1", "nvram set vpn_client1_enable=0", "nvram set vpn_clientx_eas=2,", "nvram commit"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
	// The firmware clients stop before the copies start.
	if stop, start := strings.Index(all, "service stop_wgc 1"), strings.Index(all, "wgx2"); start >= 0 && start < stop {
		t.Error("the copy was started before the firmware client stopped")
	}
	// Taken over: nothing left to do for them, and nothing is copied twice.
	if _, err := e.TakeOverClients([]string{"wgc1"}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.Config().WireGuard); n != 2 {
		t.Errorf("a second take-over of the same client made another copy (%d tunnels)", n)
	}
}
