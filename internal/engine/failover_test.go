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
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc1" {
		t.Fatalf("initial = %q", got)
	}
	st["wgc1"] = bad
	if got, _ := Select(p, "wgc1", time.Time{}, st, s, now); got != "wgc2" {
		t.Fatalf("failover = %q", got)
	}
	// primary back but not long enough
	st["wgc1"] = ok("US", 30*time.Second)
	if got, _ := Select(p, "wgc2", time.Time{}, st, s, now); got != "wgc2" {
		t.Fatalf("premature failback = %q", got)
	}
	st["wgc1"] = ok("US", 5*time.Minute)
	if got, _ := Select(p, "wgc2", time.Time{}, st, s, now); got != "wgc1" {
		t.Fatalf("failback = %q", got)
	}
	s.AutoFailback = false
	if got, _ := Select(p, "wgc2", time.Time{}, st, s, now); got != "wgc2" {
		t.Fatalf("failback disabled = %q", got)
	}
	s.AutoFailback = true
	// wrong exit country disqualifies
	st["wgc1"] = ok("CA", time.Hour)
	got, cands := Select(p, "wgc1", time.Time{}, st, s, now)
	if got != "wgc2" || cands[0].OK || cands[0].Reason == "" {
		t.Fatalf("country check = %q %+v", got, cands)
	}
	// unknown country passes unless strict
	st["wgc1"] = ok("", time.Hour)
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc1" {
		t.Fatalf("unknown country lenient = %q", got)
	}
	s.GeoStrict = true
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc2" {
		t.Fatalf("unknown country strict = %q", got)
	}
	// nothing healthy
	if got, _ := Select(p, "wgc2", time.Time{}, map[string]health.Status{}, s, now); got != "" {
		t.Fatalf("none = %q", got)
	}
}

func TestMatchDomain(t *testing.T) {
	c := config.Default()
	c.Policies = []config.Policy{
		{ID: 1, Name: "a", Enabled: true, Domains: []string{"example.com", "!=ads.example.com"}},
		{ID: 2, Name: "b", Enabled: true, Domains: []string{"**.example.com", "/^cdn\\d+\\.akamai\\.net$/"}},
		{ID: 3, Name: "c", Enabled: false, Domains: []string{"cdn.video.example.com"}},
		{ID: 4, Name: "d", Enabled: true, IgnoreCNAME: true, Domains: []string{"~edge"}},
	}
	if p, r, _, ok := MatchDomain(c, "x.cdn.video.example.com"); !ok || p.ID != 1 || r.Rule != "example.com" {
		t.Fatalf("first policy should win: %v %+v %v", p.ID, r, ok)
	}
	// exclusion in policy 1 falls through to policy 2
	if p, r, excl, ok := MatchDomain(c, "ads.example.com"); !ok || p.ID != 2 || r.Rule != "**.example.com" || len(excl) != 1 {
		t.Fatalf("exclusion fallthrough: %v %+v %v %v", p.ID, r, excl, ok)
	}
	// CNAME chain matching
	if p, r, _, ok := MatchDomain(c, "play.partner.tv", "cdn12.akamai.net"); !ok || p.ID != 2 || r.Name != "cdn12.akamai.net" {
		t.Fatalf("cname: %v %+v %v", p.ID, r, ok)
	}
	// IgnoreCNAME: policy 4 only looks at the query name
	if _, _, _, ok := MatchDomain(c, "play.partner.tv", "edge.cdn.tv"); ok {
		t.Fatal("ignore_cname policy matched via chain")
	}
	if _, _, _, ok := MatchDomain(c, "notexample.com"); ok {
		t.Fatal("suffix without dot boundary matched")
	}
}

func TestSelectAuto(t *testing.T) {
	s := config.DefaultSettings()
	now := time.Now()
	long := now.Add(-time.Hour)
	m := func(rtt, loss, mbps float64) health.Status {
		return health.Status{Healthy: true, HealthySince: long, RTTMs: rtt, Loss: loss, ThroughputMbps: mbps}
	}
	p := config.Policy{Tunnels: []string{"wgc1", "wgc2", "wgc3"}, Selection: config.SelectLatency}

	// Nothing measured: list order.
	st := map[string]health.Status{"wgc1": {Healthy: true, HealthySince: long}, "wgc2": {Healthy: true, HealthySince: long}}
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc1" {
		t.Fatalf("unmeasured = %q", got)
	}
	// Initial pick: lowest latency, not list order.
	st = map[string]health.Status{"wgc1": m(80, 0, 0), "wgc2": m(30, 0, 0), "wgc3": m(50, 0, 0)}
	got, cands := Select(p, "", time.Time{}, st, s, now)
	if got != "wgc2" || cands[1].Score != 1 || cands[0].Score < 2.6 {
		t.Fatalf("latency = %q %+v", got, cands)
	}
	// Loss counts against a tunnel: 30ms with 50% loss = 60ms.
	st["wgc2"] = m(30, 0.5, 0)
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc3" {
		t.Fatalf("lossy = %q", got)
	}

	// Hysteresis on a working tunnel.
	st = map[string]health.Status{"wgc1": m(50, 0, 0), "wgc2": m(45, 0, 0)}
	if got, _ := Select(p, "wgc1", long, st, s, now); got != "wgc1" {
		t.Fatalf("switched for 10%% = %q", got)
	}
	st["wgc2"] = m(30, 0, 0)
	if got, _ := Select(p, "wgc1", now.Add(-time.Minute), st, s, now); got != "wgc1" {
		t.Fatalf("switched before auto_switch_hold = %q", got)
	}
	if got, _ := Select(p, "wgc1", long, st, s, now); got != "wgc2" {
		t.Fatalf("40%% better after hold = %q", got)
	}
	// The better tunnel must have been healthy for failback_hold.
	h := st["wgc2"]
	h.HealthySince = now.Add(-10 * time.Second)
	st["wgc2"] = h
	if got, _ := Select(p, "wgc1", long, st, s, now); got != "wgc1" {
		t.Fatalf("switched to a fresh tunnel = %q", got)
	}
	// Current down: straight to the best, no hold.
	st["wgc1"] = health.Status{Reason: "interface down"}
	st["wgc3"] = m(90, 0, 0)
	if got, _ := Select(p, "wgc1", now, st, s, now); got != "wgc2" {
		t.Fatalf("failover = %q", got)
	}

	// Speed: highest throughput; unmeasured tunnels are not picked.
	p.Selection = config.SelectSpeed
	st = map[string]health.Status{"wgc1": m(20, 0, 50), "wgc2": m(80, 0, 200), "wgc3": m(10, 0, 0)}
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc2" {
		t.Fatalf("speed = %q", got)
	}
	// Balanced: 2x latency for 4x throughput wins; 3x latency for 1.2x does not.
	p.Selection = config.SelectBalanced
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc3" {
		// wgc3 is not speed tested yet: it counts as best on throughput.
		t.Fatalf("balanced unmeasured = %q", got)
	}
	st["wgc3"] = m(10, 0, 10)
	st["wgc1"] = m(20, 0, 200)
	st["wgc2"] = m(30, 0, 240)
	got, cands = Select(p, "", time.Time{}, st, s, now)
	if got != "wgc1" {
		t.Fatalf("balanced = %q %+v", got, cands)
	}

	// Priority selection ignores the metrics.
	p.Selection = config.SelectPriority
	if got, _ := Select(p, "", time.Time{}, st, s, now); got != "wgc1" {
		t.Fatalf("priority = %q", got)
	}
	st["wgc1"] = m(500, 0.5, 1)
	if got, cands := Select(p, "", time.Time{}, st, s, now); got != "wgc1" || cands[0].Score != 0 {
		t.Fatalf("priority with metrics = %q %+v", got, cands)
	}
}
