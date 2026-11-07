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

// share=: the session is also routed for other devices, and a connection
// from one of them keeps it alive.
func TestSessionShare(t *testing.T) {
	e, rec := sessionEngine(t)
	if _, err := e.UpdateConfig(func(c *config.Config) error {
		c.Groups = []config.Group{{Name: "kids", MACs: []string{"aa:bb:cc:00:00:31", "192.168.50.31"}}}
		c.Policies[0].Domains = []string{"session[share=kids;share=192.168.50.40]:**.akamaized.net"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r := e.domainSet(e.runtime().Policies[0]).MatchAny("a1.akamaized.net")
	rec.Commands = nil
	if err := e.AddSessions(1, "192.168.50.23", []string{"203.0.113.80"}, SessionRule, r.Rule, "a1.akamaized.net", r.Opts); err != nil {
		t.Fatal(err)
	}
	w := strings.Join(chainWrites(rec), "\n")
	for _, want := range []string{
		"-A SNAKE_Q1 -s 192.168.50.23 -d 203.0.113.80 -g SNAKE_M1",
		"-A SNAKE_Q1 -m mac --mac-source aa:bb:cc:00:00:31 -d 203.0.113.80 -g SNAKE_M1",
		"-A SNAKE_Q1 -s 192.168.50.31 -d 203.0.113.80 -g SNAKE_M1",
		"-A SNAKE_Q1 -s 192.168.50.40 -d 203.0.113.80 -g SNAKE_M1",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("missing %q in\n%s", want, w)
		}
	}
	// A shared device's connection renews the session.
	start := time.Now()
	e.refreshSessions(strings.NewReader(conn("192.168.50.40", "203.0.113.80")), start.Add(50*time.Second))
	e.refreshSessions(strings.NewReader(""), start.Add(100*time.Second))
	if len(e.Sessions(1)) != 1 {
		t.Fatal("shared device's connection did not keep the session")
	}
	// global: one rule for every device of the policy.
	if err := e.AddSessions(1, "192.168.50.23", []string{"203.0.113.81"}, SessionRule, "r", "n", match.Opts{Share: []string{"global", "kids"}}); err != nil {
		t.Fatal(err)
	}
	if pairs := e.sessionPairs(1, false); !containsPair(pairs, [2]string{"", "203.0.113.81"}) || containsPair(pairs, [2]string{"-s 192.168.50.23", "203.0.113.81"}) {
		t.Fatalf("global share pairs %v", pairs)
	}
	// Unknown group: rejected by the config.
	if _, err := e.UpdateConfig(func(c *config.Config) error {
		c.Policies[0].Domains = []string{"session[share=nope]:x.example"}
		return nil
	}); err == nil || !strings.Contains(err.Error(), "share=nope: no device group") {
		t.Fatalf("err = %v", err)
	}
}

func containsPair(ps [][2]string, p [2]string) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// drop[...]: blocks for the asking device (and share= devices); blocked
// attempts (rule counters) renew it; it ends a TTL after the last one.
func TestDropSessions(t *testing.T) {
	e, rec := sessionEngine(t)
	if _, err := e.UpdateConfig(func(c *config.Config) error {
		c.Policies[0].Domains = []string{"example.com", "drop[ttl=60;share=192.168.50.40]:ads.example.net"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Joined(), "-A SNAKE_FWD -i br+ -j SNAKE_D1") {
		t.Fatalf("no drop session chain jump:\n%s", rec.Joined())
	}
	r := e.domainSet(e.runtime().Policies[0]).MatchAny("x.ads.example.net")
	rec.Commands = nil
	if act, err := e.RouteAction(1, "192.168.50.23", []string{"203.0.113.9"}, r.Rule, "x.ads.example.net", r.Name); err != nil || act != "drop" || !r.Route {
		t.Fatalf("%q %v (match %+v)", act, err, r)
	}
	w := rec.Joined()
	for _, want := range []string{"*filter\n:SNAKE_D1 - [0:0]",
		"-A SNAKE_D1 -s 192.168.50.23 -d 203.0.113.9 -p tcp -j REJECT --reject-with tcp-reset",
		"-A SNAKE_D1 -s 192.168.50.40 -d 203.0.113.9 -j REJECT --reject-with icmp-port-unreachable"} {
		if !strings.Contains(w, want) {
			t.Errorf("missing %q in\n%s", want, w)
		}
	}
	if strings.Contains(w, "-g SNAKE_M1") {
		t.Error("drop session written as a route")
	}
	// Blocked attempts renew it.
	start := time.Now()
	rec.Responses = map[string]string{"iptables-save -c -t filter": "[3:180] -A SNAKE_D1 -s 192.168.50.40/32 -d 203.0.113.9/32 -p tcp -j REJECT --reject-with tcp-reset\n"}
	e.refreshSessions(strings.NewReader(""), start.Add(50*time.Second))
	e.refreshSessions(strings.NewReader(""), start.Add(100*time.Second)) // counter unchanged since
	if len(e.Sessions(1)) != 1 {
		t.Fatal("blocked attempt did not renew the drop session")
	}
	e.refreshSessions(strings.NewReader(""), start.Add(115*time.Second))
	if len(e.Sessions(1)) != 0 {
		t.Fatal("drop session kept after its TTL")
	}
}

// ttl=-1: sessions never expire; set=1/0/toggle turn them on, off or flip
// them at each lookup; rules matching one lookup apply top to bottom; they
// survive a restart.
func TestPermanentSessions(t *testing.T) {
	e, _ := sessionEngine(t)
	if _, err := e.UpdateConfig(func(c *config.Config) error {
		c.Policies[0].Domains = []string{"example.com",
			"route[ttl=-1]:**.both.example",
			"drop[ttl=-1]:=x.both.example",
			"route[ttl=-1;set=toggle]:switch.example",
			"route[ttl=-1;set=0]:=off.switch.example",
			"drop[ttl=-1;set=0]:=keep.example",
			"route[ttl=60]:keep.example"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	set := e.domainSet(e.runtime().Policies[0])
	look := func(name, addr string) string {
		t.Helper()
		r := set.MatchAny(name)
		act, err := e.RouteAction(1, "192.168.50.23", []string{addr}, r.Rule, name, r.Name)
		if err != nil {
			t.Fatal(err)
		}
		return act
	}
	// Both rules match x.both.example: the drop below the route wins.
	if a := look("x.both.example", "203.0.113.1"); a != "drop" {
		t.Errorf("x.both.example: %q", a)
	}
	if a := look("y.both.example", "203.0.113.2"); a != "route" {
		t.Errorf("y.both.example: %q", a)
	}
	// toggle flips; a later set=0 rule turns it off.
	for i, want := range []string{"route", "", "route"} {
		if a := look("switch.example", "203.0.113.3"); a != want {
			t.Errorf("toggle %d: %q, want %q", i, a, want)
		}
	}
	if a := look("off.switch.example", "203.0.113.3"); a != "" {
		t.Errorf("toggle then set=0 (both match, top to bottom): %q", a)
	}
	// set=0 on drop leaves a route session alone; a timed rule does not
	// shorten a permanent session.
	if a := look("keep.example", "203.0.113.4"); a != "route" {
		t.Errorf("keep.example: %q", a)
	}
	if a := look("y.both.example", "203.0.113.4"); a != "route" {
		t.Fatal(a)
	}
	_ = look("keep.example", "203.0.113.4")
	// Never expire.
	e.refreshSessions(strings.NewReader(""), time.Now().Add(30*24*time.Hour))
	perm := 0
	for _, s := range e.Sessions(1) {
		if !s.Permanent {
			t.Errorf("timed session survived: %+v", s)
		}
		perm++
	}
	if perm != 3 {
		t.Fatalf("permanent sessions: %+v", e.Sessions(1))
	}
	// Saved and restored.
	e2 := New(e.P, &system.Recorder{})
	if err := e2.Load(); err != nil {
		t.Fatal(err)
	}
	if n := len(e2.Sessions(1)); n != 3 {
		t.Fatalf("restored %d permanent sessions", n)
	}
}
