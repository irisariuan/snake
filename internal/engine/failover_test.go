package engine

import (
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/health"
)

func TestSelect(t *testing.T) {
	s := config.DefaultSettings()
	now := time.Now()
	p := config.Policy{Tunnels: []string{"wgc1", "wgc2", "ovpnc1"}, ExpectedCountry: "US"}
	ok := func(cc string, since time.Duration) health.Status {
		return health.Status{Healthy: true, Country: cc, HealthySince: now.Add(-since)}
	}
	bad := health.Status{Reason: "interface down"}

	st := map[string]health.Status{"wgc1": ok("US", time.Hour), "wgc2": ok("US", time.Hour)}
	if got, _ := Select(p, "", st, s, now); got != "wgc1" {
		t.Fatalf("initial = %q", got)
	}
	st["wgc1"] = bad
	if got, _ := Select(p, "wgc1", st, s, now); got != "wgc2" {
		t.Fatalf("failover = %q", got)
	}
	// primary back but not long enough
	st["wgc1"] = ok("US", 30*time.Second)
	if got, _ := Select(p, "wgc2", st, s, now); got != "wgc2" {
		t.Fatalf("premature failback = %q", got)
	}
	st["wgc1"] = ok("US", 5*time.Minute)
	if got, _ := Select(p, "wgc2", st, s, now); got != "wgc1" {
		t.Fatalf("failback = %q", got)
	}
	s.AutoFailback = false
	if got, _ := Select(p, "wgc2", st, s, now); got != "wgc2" {
		t.Fatalf("failback disabled = %q", got)
	}
	s.AutoFailback = true
	// wrong exit country disqualifies
	st["wgc1"] = ok("CA", time.Hour)
	got, cands := Select(p, "wgc1", st, s, now)
	if got != "wgc2" || cands[0].OK || cands[0].Reason == "" {
		t.Fatalf("country check = %q %+v", got, cands)
	}
	// unknown country passes unless strict
	st["wgc1"] = ok("", time.Hour)
	if got, _ := Select(p, "", st, s, now); got != "wgc1" {
		t.Fatalf("unknown country lenient = %q", got)
	}
	s.GeoStrict = true
	if got, _ := Select(p, "", st, s, now); got != "wgc2" {
		t.Fatalf("unknown country strict = %q", got)
	}
	// nothing healthy
	if got, _ := Select(p, "wgc2", map[string]health.Status{}, s, now); got != "" {
		t.Fatalf("none = %q", got)
	}
}

func TestMatchDomain(t *testing.T) {
	c := config.Default()
	c.Policies = []config.Policy{
		{ID: 1, Name: "a", Enabled: true, Domains: []string{"example.com"}},
		{ID: 2, Name: "b", Enabled: true, Domains: []string{"video.example.com"}},
		{ID: 3, Name: "c", Enabled: false, Domains: []string{"cdn.video.example.com"}},
	}
	if p, d, ok := MatchDomain(c, "x.cdn.video.example.com"); !ok || p.ID != 2 || d != "video.example.com" {
		t.Fatalf("got %v %q %v", p.ID, d, ok)
	}
	if _, _, ok := MatchDomain(c, "notexample.com"); ok {
		t.Fatal("suffix without dot boundary matched")
	}
}
