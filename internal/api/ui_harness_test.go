//go:build uiharness

package api

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/health"
	"github.com/irisariuan/snake/internal/learn"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/update"
)

func TestUIHarness(t *testing.T) {
	dir := t.TempDir()
	b, _ := os.ReadFile("../../testdata/config.json")
	var c config.Config
	_ = json.Unmarshal(b, &c)
	c.ApplyDefaults()
	// snake's own WireGuard tunnel (dummy keys).
	c.WireGuard = []config.WireGuard{{ID: "wgx1", Name: "Tokyo", Enabled: true, Conf: "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.64.1.2/32\nDNS = 10.64.0.1\n\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = jp-tyo.example.net:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"}}
	c.OpenVPN = []config.OpenVPN{{ID: "ovx1", Name: "Paris", Enabled: true, Username: "alice", Password: "pw",
		Conf: "client\ndev tun\nproto udp\nremote fr1.example.net 1194\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n</ca>\n"}}
	c.Policies[0].Tunnels = append(c.Policies[0].Tunnels, "ovx1")
	// A realistic household for the device pickers.
	c.Devices = append(c.Devices,
		config.Device{Name: "Living-room TV", MAC: "aa:bb:cc:00:00:02"},
		config.Device{Name: "Pixel 8", MAC: "aa:bb:cc:00:00:23"},
		config.Device{Name: "iPad (kids)", MAC: "aa:bb:cc:00:00:31"},
		config.Device{Name: "Switch", MAC: "aa:bb:cc:00:00:09"},
		config.Device{Name: "Work laptop", MAC: "aa:bb:cc:00:00:40"},
		config.Device{Name: "Printer", MAC: "aa:bb:cc:00:00:50"})
	c.Groups = append(c.Groups, config.Group{Name: "kids", MACs: []string{"aa:bb:cc:00:00:31", "aa:bb:cc:00:00:09"}})
	c.Normalize()
	_ = config.Save(filepath.Join(dir, "config.json"), &c)
	rec := &system.Recorder{Responses: map[string]string{"nvram get wan0_ipaddr": "198.51.100.20",
		// VPN server clients for the device picker: a WireGuard peer and an OpenVPN subnet.
		"nvram show":          "wgs1_enable=1\nwgs1_c1_enable=1\nwgs1_c1_name=Phone abroad\nwgs1_c1_addr=10.6.0.2/32\nvpn_server1_sn=10.8.0.0\nvpn_server1_nm=255.255.255.0\nvpn_server1_state=2\n",
		"ipset list SNK_1_d4": "Name: SNK_1_d4\nType: hash:net\nNumber of entries: 4\nMembers:\n54.155.178.5\n23.246.50.141\n52.31.4.200\n203.0.113.99\n",
		"ipset list SNK_1_r4": "Name: SNK_1_r4\nNumber of entries: 2\nMembers:\n81.2.69.160 timeout 412\n81.2.69.161 timeout 75\n"}}
	now0 := time.Now()
	recs, _ := json.Marshal([]map[string]any{
		{"set": "SNK_1_d4", "addr": "54.155.178.5", "name": "www.netflix.com", "matched": "www.netflix.com", "rule": "netflix.com", "client": "192.168.50.23", "first_seen": now0.Add(-3 * time.Hour), "last_seen": now0.Add(-2 * time.Minute), "hits": 14},
		{"set": "SNK_1_d4", "addr": "23.246.50.141", "name": "play.partner.tv", "matched": "x1.cdn.nflxvideo.net", "rule": "**.nflxvideo.net", "client": "192.168.50.40", "first_seen": now0.Add(-time.Hour), "last_seen": now0.Add(-10 * time.Minute), "hits": 2},
		{"set": "SNK_1_d4", "addr": "52.31.4.200", "name": "api-global.netflix.com", "matched": "api-global.netflix.com", "rule": "netflix.com", "client": "192.168.50.23", "first_seen": now0.Add(-time.Hour), "last_seen": now0.Add(-30 * time.Minute), "hits": 5},
	})
	_ = os.WriteFile(filepath.Join(dir, "dnslearn.json"), recs, 0o600)
	e := engine.New(engine.DefaultPaths(dir), rec)
	e.DryRun = true
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	e.DetectCaps()
	e.Monitor().Set(health.Status{Tunnel: "wgc1", Iface: "wgc1", Exists: true, Up: true, LinkOK: true, ProbeOK: true, Healthy: true, ExitIP: "203.0.113.9", Country: "US", ProbeRTT: "38ms", Handshake: time.Now().Add(-40 * time.Second), GeoChecked: time.Now()})
	e.Monitor().Set(health.Status{Tunnel: "wgx1", Iface: "wgx1", Exists: true, Up: true, LinkOK: true, ProbeOK: true, Healthy: true, ExitIP: "198.51.100.61", Country: "JP", ProbeRTT: "121ms", Handshake: time.Now().Add(-70 * time.Second), GeoChecked: time.Now()})
	e.Monitor().Set(health.Status{Tunnel: "ovx1", Iface: "ovx1", Exists: true, Up: true, LinkOK: true, ProbeOK: true, Healthy: true, ExitIP: "192.0.2.80", Country: "FR", ProbeRTT: "30ms", GeoChecked: time.Now()})
	e.Monitor().Set(health.Status{Tunnel: "ovpnc2", Iface: "tun12", Exists: true, Reason: "interface down"})
	e.Monitor().Set(health.Status{Tunnel: "wgc2", Iface: "wgc2", Exists: true, Up: true, LinkOK: true, ProbeOK: true, Healthy: true, ExitIP: "192.0.2.44", Country: "GB"})
	e.Decide()
	e.LoadDNSRecords()
	now := time.Now()
	_ = e.EditLearnings(func(st *learn.Store) error {
		o := learn.Observation{Addr: "66.22.196.34", Client: "192.168.50.23", Policy: 1, Time: now.Add(-50 * time.Minute)}
		id, _ := st.Create(o, "netflix.com · Pixel 8", []learn.Origin{
			{Time: o.Time, PolicyID: 1, Policy: "Netflix US", Tunnel: "wgc1", ClientIP: o.Client, MAC: "aa:bb:cc:00:00:23", Device: "Pixel 8", Trigger: true,
				Destinations: []string{"www.netflix.com (54.155.178.5)", "ipv4-c042-lhr001.oca.nflxvideo.net (23.246.50.141)"}},
			{Time: o.Time, PolicyID: 2, Policy: "Disney UK TV", Tunnel: "wgc2", ClientIP: o.Client, MAC: "aa:bb:cc:00:00:23", Device: "Pixel 8", Destinations: []string{"disneyplus.com (34.120.10.2)"}},
		})
		st.Observe(learn.Observation{Addr: "66.22.196.35", Client: o.Client, Policy: 1, Time: o.Time.Add(time.Second)}, time.Minute)
		st.Activity(map[string]bool{"66.22.196.34": true}, nil, now.Add(-20*time.Second))
		pin := true
		_ = st.Update(id, learn.Patch{Pinned: &pin})
		o2 := learn.Observation{Addr: "74.125.250.129", Client: "192.168.50.40", Policy: 2, Time: now.Add(-5 * time.Hour)}
		id2, _ := st.Create(o2, "Disney UK TV · Apple TV", []learn.Origin{{Time: o2.Time, PolicyID: 2, Policy: "Disney UK TV", Tunnel: "wgc2", ClientIP: o2.Client, MAC: "aa:bb:cc:00:00:01", Device: "Apple TV", Trigger: true}})
		name, notes, ttl := "Google STUN (shared)", "public STUN server, also used by Meet", 7200
		_ = st.Update(id2, learn.Patch{Name: &name, Notes: &notes, TTL: &ttl})
		_ = st.AddServers(id2, []string{"2001:4860:4864:5:8000::1"}, now)
		off := false
		id3, _ := st.New(learn.Patch{Name: &name}, []string{"198.51.100.77"}, now)
		n3 := "Old relay (disabled)"
		_ = st.Update(id3, learn.Patch{Name: &n3, Enabled: &off})
		return nil
	})
	// Fake GitHub releases: v1.1.0 is available, v0.9.0 is the rollback copy.
	gh := http.NewServeMux()
	gh.HandleFunc("/repos/irisariuan/snake/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.1.0", "html_url": "https://github.com/irisariuan/snake/releases/tag/v1.1.0",
			"body": "## What's changed\n* Emergency disable switch\n* Self-update and rollback", "published_at": time.Now().Add(-26 * time.Hour)})
	})
	gh.HandleFunc("/repos/irisariuan/snake/releases", func(w http.ResponseWriter, r *http.Request) {
		var rels []map[string]any
		for i, v := range []string{"v1.1.0", "v1.0.0", "v0.9.0", "v0.8.0-rc1", "v0.7.0"} {
			rel := map[string]any{"tag_name": v, "html_url": "https://github.com/irisariuan/snake/releases/tag/" + v, "body": "Changes in " + v,
				"published_at": time.Now().Add(-time.Duration(i*20+1) * 24 * time.Hour), "prerelease": strings.Contains(v, "-rc")}
			if v != "v0.7.0" { // too old: no binary for this CPU
				rel["assets"] = []map[string]string{{"name": update.Asset(), "browser_download_url": "x"}, {"name": update.SumsAsset, "browser_download_url": "x"}}
			}
			rels = append(rels, rel)
		}
		_ = json.NewEncoder(w).Encode(rels)
	})
	ghl, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = http.Serve(ghl, gh) }()
	bin := filepath.Join(dir, "snake")
	_ = os.WriteFile(bin, []byte("#!/bin/sh\necho snake v1.0.0\n"), 0o755)
	_ = os.WriteFile(bin+".prev", []byte("#!/bin/sh\necho snake v0.9.0\n"), 0o755)
	u := &update.Updater{Bin: bin, Current: "v1.0.0", APIBase: "http://" + ghl.Addr().String()}
	s := &Server{E: e, Token: "testtoken", U: u}
	t.Log("listening on 127.0.0.1:18444")
	_ = http.ListenAndServe("127.0.0.1:18444", s.routes(true))
}
