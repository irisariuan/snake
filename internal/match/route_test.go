package match

import (
	"strings"
	"testing"
	"time"
)

func TestRouteRules(t *testing.T) {
	lines := []string{
		"netflix.com",
		"route[ttl=5m;onlookup=1]:or:(",
		"  **.akamaized.net,   # CDN",
		"  /^ipv4-c\\d+\\.oca\\.example$/",
		");",
		"if:or:(disneyplus.com, and:(hulu.com, not:=help.hulu.com))",
		"# a comment",
		"route:(or:(a.example, b.example), not:=bad.a.example, and:(not:~ads, ~cdn)); if:=trigger.example",
		"session[ttl=90;onlookup=0]:x.example",
		"plain.example",
	}
	g := Group(lines)
	if len(g) != 6 || g[1].First != 1 || !strings.HasSuffix(g[1].Text, "if:or:(disneyplus.com, and:(hulu.com, not:=help.hulu.com))") || g[3].First != 7 {
		for _, l := range g {
			t.Logf("%d: %q", l.First, l.Text)
		}
		t.Fatalf("grouping")
	}
	s, errs := Compile(lines)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(s.Routes) != 2 || len(s.Session) != 1 || !s.HasSessions() || !s.NeedsInspector() {
		t.Fatalf("compiled %+v", s)
	}
	r0 := s.Routes[0]
	// The old route:...;if:... form is read as if:...;then:route:....
	if o := r0.Then.Opts; o.TTL != 5*time.Minute || !o.OnLookup || r0.Then.Kind != ActRoute ||
		r0.Raw != "if:or:(disneyplus.com, and:(hulu.com, not:=help.hulu.com));\nthen:route[ttl=5m;onlookup=1]:or:(**.akamaized.net,/^ipv4-c\\d+\\.oca\\.example$/)" {
		t.Fatalf("route options %+v %q", o, r0.Raw)
	}
	if r1 := s.Routes[1]; r1.Raw != "if:=trigger.example;then:route:(or:(a.example, b.example), not:=bad.a.example, and:(not:~ads, ~cdn))" {
		t.Fatalf("converted %q", r1.Raw)
	}
	if s.Session[0].Opts.TTL != 90*time.Second || s.Session[0].Raw != "session[ttl=90s]:x.example" {
		t.Fatalf("session options %+v %q", s.Session[0].Opts, s.Session[0].Raw)
	}
	check := func(name, want string) {
		t.Helper()
		r := s.MatchAny(name)
		got := "none"
		switch {
		case len(r.Cond) > 0:
			got = "cond"
		case r.Route:
			got = "route"
		case r.Session:
			got = "session"
		case r.Matched:
			got = "include"
		}
		if got != want {
			t.Errorf("%s: %s (%+v), want %s", name, got, r, want)
		}
	}
	check("www.disneyplus.com", "cond") // if: atoms are routed for everyone
	check("www.hulu.com", "cond")
	check("help.hulu.com", "cond") // hulu.com matches; the not: only matters for the condition
	check("trigger.example", "cond")
	check("e1.akamaized.net", "route")
	check("ipv4-c12.oca.example", "route")
	check("a.example", "none") // and: also needs ~cdn
	check("cdn.a.example", "route")
	check("bad.a.example", "none")     // not:=bad.a.example
	check("ads.cdn.b.example", "none") // and:(not:~ads, ~cdn)
	check("cdn.b.example", "route")
	check("b.example", "none") // ~cdn missing
	check("www.netflix.com", "include")
	check("x.example", "session")
	// Cond hits name the atoms the addresses count for.
	r := s.MatchAny("www.hulu.com")
	if len(r.Cond) != 1 || r.Cond[0].Rule != r0.Raw || r.Cond[0].Atom != 2 {
		t.Fatalf("cond hits %+v", r.Cond)
	}
	// The condition: atoms 1 (disneyplus), 2 (hulu), 3 (help.hulu, negated).
	on := func(ids ...int) func(*Expr) bool {
		return func(a *Expr) bool {
			for _, i := range ids {
				if a.ID == i {
					return true
				}
			}
			return false
		}
	}
	for ids, want := range map[string]bool{"1": true, "2": true, "2,3": false, "": false, "1,3": true} {
		var nums []int
		for _, f := range strings.Split(ids, ",") {
			if f != "" {
				nums = append(nums, int(f[0]-'0'))
			}
		}
		if got := r0.If.Eval(on(nums...)); got != want {
			t.Errorf("condition with atoms %s on: %v", ids, got)
		}
	}
	if b := strings.Join(s.Bases(), ","); !strings.Contains(b, "akamaized.net") || !strings.Contains(b, "disneyplus.com") {
		t.Errorf("bases %s", b)
	}
}

func TestRouteErrors(t *testing.T) {
	for want, rule := range map[string]string{
		"expected , or )":   "route:or:(a.com, b.com;if:c.com",
		"needs ( ... )":     "route:or:a.com",
		"unexpected":        "route:a.com;c.com",
		"only domain rules": "route:drop:a.com",
		"not negated":       "route:a.com;if:not:b.com",
		"unknown option":    "route[foo=1]:a.com",
		"between 10s":       "session[ttl=1]:a.com",
		"onlookup must be":  "session[onlookup=2]:a.com",
		"unterminated":      "route:/abc;if:b.com",
	} {
		var err error
		if IsRoute(rule) {
			_, err = ParseRoute(rule)
		} else {
			_, err = Parse(rule)
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", rule, want, err)
		}
	}
	// A route rule spanning lines reports its first line.
	_, errs := Compile([]string{"a.com", "route:or:(", "b.com,", "drop:c.com", ")"})
	if len(errs) != 1 || errs[0].Index != 1 {
		t.Fatalf("errors %+v", errs)
	}
}

func TestShareOption(t *testing.T) {
	p, err := Parse("session[share=kids,share=10.6.0.2;share=AA-BB-CC-00-00-31,share=group:kids,share=10.8.0.5/24]:x.example")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Opts.Share, " "); got != "kids 10.6.0.2 aa:bb:cc:00:00:31 10.8.0.0/24" {
		t.Fatalf("shares %q", got)
	}
	if p.Raw != "session[share=kids;share=10.6.0.2;share=aa:bb:cc:00:00:31;share=10.8.0.0/24]:x.example" {
		t.Fatalf("raw %q", p.Raw)
	}
	r, err := ParseRoute("route[share=global]:a.example;if:b.example")
	if err != nil || len(r.Then.Opts.Share) != 1 || r.Then.Opts.Share[0] != ShareGlobal {
		t.Fatalf("route share %+v %v", r, err)
	}
	if _, err := Parse("session[share=bad/name]:x.example"); err == nil {
		t.Error("bad share accepted")
	}
}

func TestDropSessionRules(t *testing.T) {
	s, errs := Compile([]string{"drop[share=kids;ttl=5m]:ads.example.com", "drop:tracker.example", "example.com"})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if !s.HasDropSessions() || s.Drop[0].Raw != "drop[ttl=5m;share=kids]:ads.example.com" {
		t.Fatalf("drop sessions %+v", s.Drop)
	}
	r := s.MatchAny("x.ads.example.com")
	st := s.StepsFor("x.ads.example.com")
	if !r.Route || len(st) != 1 || st[0].Drop.Opts.TTL != 5*time.Minute || len(st[0].Drop.Opts.Share) != 1 {
		t.Fatalf("match %+v", r)
	}
	if r := s.MatchAny("tracker.example"); !r.Drop || !r.Opts.IsZero() {
		t.Fatalf("plain drop %+v", r)
	}
	if d := strings.Join(s.DropSuffixes(false), ","); d != "tracker.example" {
		t.Fatalf("dnsmasq drop suffixes %q (drop sessions are per device)", d)
	}
	if !s.NeedsInspector() {
		t.Error("drop sessions need the inspector")
	}
	for _, bad := range []string{"drop[share=kids]:asn:1234", "drop[ttl=2]:a.com", "!drop[ttl=5m]:a.com"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIfThenElse(t *testing.T) {
	lines := []string{
		"if:netflix.com;",
		"then:route[ttl=10m]:or:(**.akamaized.net, **.nflxvideo.net);",
		"else:drop:**.nflxvideo.net;",
		"finally:route:=help.netflix.com",
		"if:a.example",
		"then:drop[share=kids]:b.example",
		"finally:route:(c.example, not:=x.c.example)",
		"plain.example",
	}
	g := Group(lines)
	if len(g) != 3 || g[1].First != 4 {
		t.Fatalf("grouping %+v", g)
	}
	s, errs := Compile(lines)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	r := s.Routes[0]
	if r.Then.Kind != ActRoute || r.Then.Opts.TTL != 10*time.Minute || r.Else.Kind != ActDrop || r.Finally.Kind != ActRoute {
		t.Fatalf("branches %+v %+v %+v", r.Then, r.Else, r.Finally)
	}
	if !s.HasDropSessions() || !s.HasConds() {
		t.Fatal("drop branch / condition")
	}
	kind := func(a *Action) string {
		if a == nil {
			return "-"
		}
		return a.Kind
	}
	for _, c := range []struct {
		name string
		cond bool
		want string
	}{
		{"e1.akamaized.net", true, "route"},
		{"e1.akamaized.net", false, "-"},
		{"x.nflxvideo.net", true, "route"},
		{"x.nflxvideo.net", false, "drop"},
		{"help.netflix.com", true, "route"}, // finally: either way
		{"help.netflix.com", false, "route"},
	} {
		if got := kind(r.Pick(c.cond, c.name)); got != c.want {
			t.Errorf("%s cond=%v: %s, want %s", c.name, c.cond, got, c.want)
		}
	}
	// Names in the condition are routed for everyone; branch names go to the
	// engine.
	if m := s.MatchAny("www.netflix.com"); len(m.Cond) == 0 {
		t.Errorf("netflix.com: %+v", m)
	}
	if m := s.MatchAny("x.nflxvideo.net"); !m.Route || m.Rule != r.Raw {
		t.Errorf("nflxvideo: %+v", m)
	}
	r2 := s.Routes[1]
	if r2.Else != nil || kind(r2.Pick(false, "b.example")) != "-" || kind(r2.Pick(true, "b.example")) != "drop" ||
		kind(r2.Pick(false, "c.example")) != "route" || r2.Pick(true, "x.c.example") != nil {
		t.Fatalf("second rule %+v", r2)
	}
	if b := strings.Join(s.Bases(), ","); strings.Contains(b, "b.example") || !strings.Contains(b, "c.example") {
		t.Errorf("bases %s (drop branches need no tunnel DNS)", b)
	}
	for want, rule := range map[string]string{
		"expected ;then:":       "if:a.com",
		"needs an action":       "if:a.com;then:b.com",
		"order if:":             "if:a.com;then:route:b.com;finally:route:c.com;else:drop:d.com",
		"only domain rules":     "if:a.com;then:route:drop:b.com",
		"not negated":           "if:not:a.com;then:route:b.com",
		"unknown option":        "if:a.com;then:drop[x=1]:b.com",
		"expected ;then:ACTION": "if:a.com;else:route:b.com",
	} {
		if _, err := ParseRoute(rule); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", rule, want, err)
		}
	}
	if !IsLegacyRoute("route:a.com;if:b.com") || IsLegacyRoute("route:a.com") || IsLegacyRoute("if:b.com;then:route:a.com") {
		t.Error("IsLegacyRoute")
	}
}

func TestSetOption(t *testing.T) {
	r, err := ParseRoute("if:a.example;then:route[ttl=-1;set=on]:b.example;else:drop[ttl=-5m,set=toggle]:b.example")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Then.Opts.Permanent() || r.Then.Opts.SetMode() != SetOn || r.Else.Opts.SetMode() != SetToggle {
		t.Fatalf("opts %+v %+v", r.Then.Opts, r.Else.Opts)
	}
	p, err := Parse("drop[ttl=-1;set=0;share=kids]:ads.example")
	if err != nil || p.Raw != "drop[ttl=-1;set=0;share=kids]:ads.example" || p.Opts.SetMode() != SetOff {
		t.Fatalf("%+v %v", p, err)
	}
	if p, _ := Parse("drop[set=1;ttl=-1]:x.example"); p.Raw != "drop[ttl=-1]:x.example" {
		t.Fatalf("canonical %q (set=1 is the default)", p.Raw)
	}
	for want, rule := range map[string]string{
		"needs a negative ttl":   "drop[set=0]:a.example",
		"onlookup has no effect": "drop[ttl=-1;onlookup=1]:a.example",
		"set must be":            "drop[ttl=-1;set=2]:a.example",
		"for route and drop":     "session[ttl=-1]:a.example",
		"seconds or a duration":  "drop[ttl=-x]:a.example",
	} {
		if _, err := Parse(rule); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want %q, got %v", rule, want, err)
		}
	}
}

// Route/drop rules matching one lookup apply top to bottom.
func TestStepsOrder(t *testing.T) {
	s, errs := Compile([]string{
		"drop[ttl=-1]:=x.both.example",
		"plain.example",
		"route[ttl=-1]:**.both.example",
		"if:t.example;then:drop:**.both.example",
		"drop:blocked.example",
	})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var raws []string
	for _, st := range s.StepsFor("x.both.example") {
		raws = append(raws, st.Raw())
	}
	if strings.Join(raws, " | ") != "drop[ttl=-1]:=x.both.example | route[ttl=-1]:**.both.example | if:t.example;then:drop:**.both.example" {
		t.Fatalf("steps %q", raws)
	}
	if r := s.MatchAny("x.both.example"); !r.Route || r.Rule != "drop[ttl=-1]:=x.both.example" {
		t.Fatalf("match %+v", r)
	}
	if r := s.MatchAny("y.both.example"); !r.Route || r.Rule != "route[ttl=-1]:**.both.example" {
		t.Fatalf("match %+v", r)
	}
	if r := s.MatchAny("blocked.example"); !r.Drop || r.Route {
		t.Fatalf("plain drop %+v", r)
	}
}
