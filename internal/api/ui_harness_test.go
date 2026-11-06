//go:build uiharness

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/health"
	"github.com/irisariuan/snake/internal/learn"
	"github.com/irisariuan/snake/internal/system"
)

func TestUIHarness(t *testing.T) {
	dir := t.TempDir()
	b, _ := os.ReadFile("../../testdata/config.json")
	var c config.Config
	_ = json.Unmarshal(b, &c)
	c.ApplyDefaults()
	c.Normalize()
	_ = config.Save(filepath.Join(dir, "config.json"), &c)
	rec := &system.Recorder{Responses: map[string]string{"nvram get wan0_ipaddr": "198.51.100.20",
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
	s := &Server{E: e, Token: "testtoken"}
	t.Log("listening on 127.0.0.1:18444")
	_ = http.ListenAndServe("127.0.0.1:18444", s.routes(true))
}
