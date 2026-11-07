package engine

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/system"
)

func sessionEngine(t *testing.T) (*Engine, *system.Recorder) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Settings.PreResolve = false
	c.Settings.SessionTTL = 60
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true,
		Domains: []string{"example.com", "session:**.akamaized.net"}, Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{}
	e := New(DefaultPaths(dir), rec)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply("test"); err != nil {
		t.Fatal(err)
	}
	return e, rec
}

func chainWrites(rec *system.Recorder) []string {
	var out []string
	for _, c := range rec.Commands {
		if strings.HasPrefix(c, "iptables-restore --noflush <<EOF\n*mangle\n:SNAKE_Q1") {
			out = append(out, c)
		}
	}
	return out
}

func TestSessions(t *testing.T) {
	e, rec := sessionEngine(t)
	// The policy has a session chain in the plan.
	if !strings.Contains(rec.Joined(), "-A SNAKE_P1 -j SNAKE_Q1") {
		t.Fatalf("no session chain jump:\n%s", rec.Joined())
	}
	rec.Commands = nil
	if err := e.AddSessions(1, "192.168.50.23", []string{"203.0.113.80", "2001:db8::1"}, SessionRule, "session:**.akamaized.net", "a1.akamaized.net", match.Opts{}); err != nil {
		t.Fatal(err)
	}
	w := chainWrites(rec)
	if len(w) != 1 || !strings.Contains(w[0], "-A SNAKE_Q1 -s 192.168.50.23 -d 203.0.113.80 -g SNAKE_M1") || strings.Contains(w[0], "2001:db8::1") {
		t.Fatalf("chain write %q", w)
	}
	// Known pair: no rewrite.
	rec.Commands = nil
	_ = e.AddSessions(1, "192.168.50.23", []string{"203.0.113.80"}, SessionRule, "", "", match.Opts{})
	if len(chainWrites(rec)) != 0 {
		t.Fatal("rewrote the chain for a known session")
	}
	// TTL starts after the last connection: a live connection renews it.
	start := time.Now()
	live := "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.50.23 dst=203.0.113.80 sport=50000 dport=443 src=203.0.113.80 dst=10.2.0.2 sport=443 dport=50000 [ASSURED] mark=65536 use=1\n"
	e.refreshSessions(strings.NewReader(live), start.Add(50*time.Second))
	e.refreshSessions(strings.NewReader(""), start.Add(100*time.Second)) // 50 s after the last connection
	if n := len(e.Sessions(1)); n != 1 {
		t.Fatalf("session ended while its TTL was still running (%d)", n)
	}
	rec.Commands = nil
	e.refreshSessions(strings.NewReader(""), start.Add(115*time.Second)) // 65 s after
	if n := len(e.Sessions(1)); n != 0 {
		t.Fatalf("expired session kept (%d)", n)
	}
	if w := chainWrites(rec); len(w) != 1 || strings.Contains(w[0], "-A SNAKE_Q1") {
		t.Fatalf("expired session not removed from the chain: %q", w)
	}
	// A policy without session rules loses its sessions at the next apply.
	_ = e.AddSessions(1, "192.168.50.23", []string{"203.0.113.81"}, SessionRule, "", "", match.Opts{})
	if _, err := e.UpdateConfig(func(c *config.Config) error { c.Policies[0].Domains = []string{"example.com"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if n := len(e.Sessions(0)); n != 0 {
		t.Fatalf("sessions of a policy without a session chain kept (%d)", n)
	}
}
