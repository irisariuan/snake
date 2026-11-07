package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

const routeRule = `if:and:(netflix.com, not:=help.netflix.com);
then:route[ttl=5m]:**.akamaized.net;
else:drop[ttl=1m]:or:(**.akamaized.net, **.nflxvideo.net);
finally:route:=info.netflix.example`

func routeEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Settings.PreResolve = false
	c.Settings.SessionTTL = 60
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true,
		Domains: append(strings.Split(routeRule, "\n"), "session[ttl=2m;onlookup=1]:**.example.org"), Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	e := New(DefaultPaths(dir), &system.Recorder{})
	e.conntrackPath = filepath.Join(dir, "conntrack")
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply("test"); err != nil {
		t.Fatal(err)
	}
	return e, e.conntrackPath
}

func conn(src, dst string) string {
	return "ipv4     2 tcp      6 431999 ESTABLISHED src=" + src + " dst=" + dst + " sport=50000 dport=443 src=" + dst + " dst=10.2.0.2 sport=443 dport=50000 [ASSURED] mark=65536 use=1\n"
}

// if:B;then:route:A;else:drop:A: a device's lookup of A starts route
// sessions while it has a live connection to an address answered for B,
// drop sessions otherwise; finally: names are routed either way.
func TestRouteCondition(t *testing.T) {
	e, ct := routeEngine(t)
	p := e.runtime().Policies[0]
	set := e.domainSet(p)
	// The DNS inspector records the addresses of if: names (and routes them).
	for name, addr := range map[string]string{"www.netflix.com": "198.51.100.10", "help.netflix.com": "198.51.100.20"} {
		if r := set.MatchAny(name); len(r.Cond) == 0 || !r.Matched {
			t.Fatalf("%s: if: names are routed: %+v", name, r)
		}
		e.recordCond(p.ID, []string{addr}, set.CondHits(name))
	}
	try := func(live, name string) string {
		t.Helper()
		_ = os.WriteFile(ct, []byte(live), 0o644)
		r := set.MatchAny(name)
		if !r.Route {
			t.Fatalf("%s: route match %+v", name, r)
		}
		act, err := e.RouteAction(p.ID, "192.168.50.23", []string{"203.0.113.80"}, r.Rule, name, r.Name)
		if err != nil {
			t.Fatal(err)
		}
		return act
	}
	const cdn = "e1.akamaized.net"
	if a := try("", cdn); a != "drop" {
		t.Errorf("no live connection: %q, want the else: drop", a)
	}
	if s := e.Sessions(p.ID); len(s) != 1 || s[0].Source != SessionDrop || s[0].TTL != time.Minute {
		t.Fatalf("drop sessions %+v", s)
	}
	if a := try(conn("192.168.50.40", "198.51.100.10"), cdn); a != "drop" {
		t.Errorf("another device's connection made the condition hold: %q", a)
	}
	if a := try(conn("192.168.50.23", "198.51.100.10")+conn("192.168.50.23", "198.51.100.20"), cdn); a != "drop" {
		t.Errorf("not:=help.netflix.com ignored: %q", a)
	}
	if a := try(conn("192.168.50.23", "198.51.100.10"), "x.nflxvideo.net"); a != "drop" {
		t.Errorf("then: has no nflxvideo.net, finally: neither: nothing applies, the earlier drop stays: %q", a)
	}
	if a := try("", "info.netflix.example"); a != "route" {
		t.Errorf("finally: without the condition: %q", a)
	}
	if a := try(conn("192.168.50.23", "198.51.100.10"), cdn); a != "route" {
		t.Fatalf("condition did not hold with a live Netflix connection: %q", a)
	}
	// The route replaced the device's drop session for the address.
	routed := e.Sessions(p.ID)
	if len(routed) != 1 || routed[0].Source != SessionRule || routed[0].Client != "192.168.50.23" || routed[0].TTL != 5*time.Minute || time.Until(routed[0].Expires) < 4*time.Minute {
		t.Fatalf("sessions %+v", routed)
	}
}

// onlookup=1: the TTL counts from the lookup; live connections do not
// renew it.
func TestSessionOnLookup(t *testing.T) {
	e, _ := routeEngine(t)
	r := e.domainSet(e.runtime().Policies[0]).MatchAny("www.example.org")
	if !r.Session || !r.Opts.OnLookup || r.Opts.TTL != 2*time.Minute {
		t.Fatalf("match %+v", r)
	}
	if err := e.AddSessions(1, "192.168.50.23", []string{"203.0.113.90"}, SessionRule, r.Rule, "www.example.org", r.Opts); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	live := strings.NewReader(conn("192.168.50.23", "203.0.113.90"))
	e.refreshSessions(live, start.Add(100*time.Second))
	e.refreshSessions(strings.NewReader(conn("192.168.50.23", "203.0.113.90")), start.Add(130*time.Second))
	if n := len(e.Sessions(1)); n != 0 {
		t.Fatalf("onlookup session renewed by connections (%d left)", n)
	}
}
