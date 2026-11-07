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
	if r0.Opts.TTL != 5*time.Minute || !r0.Opts.OnLookup || !strings.HasPrefix(r0.Raw, "route[ttl=5m;onlookup=1]:or:(") {
		t.Fatalf("route options %+v %q", r0.Opts, r0.Raw)
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
		"expected if:":      "route:a.com;c.com",
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
	if err != nil || len(r.Opts.Share) != 1 || r.Opts.Share[0] != ShareGlobal {
		t.Fatalf("route share %+v %v", r, err)
	}
	if _, err := Parse("session[share=bad/name]:x.example"); err == nil {
		t.Error("bad share accepted")
	}
}
