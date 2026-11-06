package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/learn"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/webrtc"
)

func learnEngine(t *testing.T) (*Engine, *system.Recorder) {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	// Only Disney UK TV (id 2) has the device in a session window.
	rec := &system.Recorder{Fail: map[string]bool{"ipset test SNK_1_s4": true}}
	e := New(DefaultPaths(dir), rec)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	e.active = map[int]string{1: "wgc1", 2: "wgc2"}
	return e, rec
}

func lastReplace(rec *system.Recorder, set string) string {
	out := ""
	for _, c := range rec.Commands {
		if strings.HasPrefix(c, "ipset -exist restore") && strings.Contains(c, "create "+set+"_t ") {
			out = c
		}
	}
	return out
}

func TestLearningFlow(t *testing.T) {
	e, rec := learnEngine(t)
	now := time.Now()
	e.onServer(webrtc.ServerEvent{Policy: 2, Client: "192.168.50.10", Server: "203.0.113.7", Time: now})
	e.onServer(webrtc.ServerEvent{Policy: 2, Client: "192.168.50.10", Server: "203.0.113.8", Time: now.Add(time.Second)})
	groups, _ := e.Learnings()
	if len(groups) != 1 || len(groups[0].Servers) != 2 || groups[0].RouteVia != 2 {
		t.Fatalf("groups %+v", groups)
	}
	g := groups[0]
	if len(g.Origins) != 1 || g.Origins[0].PolicyID != 2 || g.Origins[0].Tunnel != "wgc2" || !g.Origins[0].Trigger {
		t.Fatalf("origins %+v", g.Origins)
	}
	if !strings.HasPrefix(g.Name, "Disney UK TV · ") {
		t.Errorf("name %q", g.Name)
	}
	if r := lastReplace(rec, "SNK_2_t4"); !strings.Contains(r, "add SNK_2_t4_t 203.0.113.7\n") || !strings.Contains(r, "add SNK_2_t4_t 203.0.113.8") {
		t.Fatalf("kernel set not synced:\n%s", r)
	}
	if p, ok := e.serverRoute("203.0.113.7"); !ok || p != 2 {
		t.Fatalf("route %d %v", p, ok)
	}
	// persisted
	if b, err := os.ReadFile(e.P.Learnings); err != nil || !strings.Contains(string(b), "203.0.113.8") {
		t.Fatalf("not saved: %v", err)
	}

	// re-route via Netflix US, then disable
	one, off := 1, false
	if err := e.EditLearnings(func(st *learn.Store) error { return st.Update(g.ID, learn.Patch{RouteVia: &one}) }); err != nil {
		t.Fatal(err)
	}
	if r := lastReplace(rec, "SNK_1_t4"); !strings.Contains(r, "203.0.113.7") {
		t.Fatalf("not moved to policy 1:\n%s", r)
	}
	if r := lastReplace(rec, "SNK_2_t4"); strings.Contains(r, "203.0.113.7") {
		t.Fatal("still in policy 2's set")
	}
	_ = e.EditLearnings(func(st *learn.Store) error { return st.Update(g.ID, learn.Patch{Enabled: &off}) })
	if p, ok := e.serverRoute("203.0.113.7"); !ok || p != 0 {
		t.Fatalf("disabled group route %d %v (want WAN)", p, ok)
	}

	// route via a policy without WebRTC tracking: falls back (unknown)
	three, on := 3, true
	_ = e.EditLearnings(func(st *learn.Store) error {
		return st.Update(g.ID, learn.Patch{RouteVia: &three, Enabled: &on})
	})
	if _, ok := e.serverRoute("203.0.113.7"); ok {
		t.Fatal("untracked route-via policy should fall back to the session's policy")
	}
	if e.ValidRouteVia(99) || !e.ValidRouteVia(0) || !e.ValidRouteVia(3) {
		t.Fatal("ValidRouteVia")
	}
}

func TestLearningExpiryViaScan(t *testing.T) {
	e, _ := learnEngine(t)
	cfg := e.rtCfg()
	cfg.Settings.STUNServerTTL = 3600
	now := time.Now()
	e.onServer(webrtc.ServerEvent{Policy: 1, Client: "192.168.50.20", Server: "198.51.100.1", Time: now})
	// live connection for 2h keeps it; then idle past the TTL removes it
	e.onScan(webrtc.Scan{Time: now.Add(2 * time.Hour), Active: map[string]bool{"198.51.100.1": true}})
	e.onScan(webrtc.Scan{Time: now.Add(2*time.Hour + 30*time.Minute)})
	if g, _ := e.Learnings(); len(g) != 1 {
		t.Fatal("expired while it had a live connection 30 min ago")
	}
	e.onScan(webrtc.Scan{Time: now.Add(3*time.Hour + time.Minute)})
	if g, _ := e.Learnings(); len(g) != 0 {
		t.Fatalf("not expired: %+v", g)
	}
	if _, ok := e.serverRoute("198.51.100.1"); ok {
		t.Fatal("expired server still routed")
	}
}

func TestImportLegacyServers(t *testing.T) {
	e, rec := learnEngine(t)
	rec.Responses = map[string]string{"ipset list SNK_1_t4": "Name: SNK_1_t4\nMembers:\n203.0.113.30 timeout 500\n"}
	e.importLegacyServers()
	g, _ := e.Learnings()
	if len(g) != 1 || g[0].Name != "Imported: Netflix US" || g[0].RouteVia != 1 || g[0].Servers[0].Addr != "203.0.113.30" {
		t.Fatalf("%+v", g)
	}
}
