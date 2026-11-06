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
	rec := &system.Recorder{Responses: map[string]string{"nvram get wan0_ipaddr": "198.51.100.20", "ipset list SNK_1_d4 -t": "Number of entries: 412"}}
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
	s := &Server{E: e, Token: "testtoken"}
	t.Log("listening on 127.0.0.1:18444")
	_ = http.ListenAndServe("127.0.0.1:18444", s.routes(true))
}
