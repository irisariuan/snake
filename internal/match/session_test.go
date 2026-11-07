package match

import (
	"strings"
	"testing"
)

func TestSessionRules(t *testing.T) {
	s, errs := Compile([]string{"netflix.com", "SESSION:**.Akamaized.net", "session:~nflxso", "drop:ads.akamaized.net", "!=ok.akamaized.net"})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if !s.HasSessions() || len(s.Session) != 2 || s.Session[0].Raw != "session:**.akamaized.net" {
		t.Fatalf("session rules %+v", s.Session)
	}
	for name, want := range map[string]string{
		"a1.akamaized.net":  "session",
		"www.netflix.com":   "include",
		"x.nflxso.net":      "session",
		"ads.akamaized.net": "drop",    // drop beats session
		"ok.akamaized.net":  "exclude", // ! beats session
		"example.org":       "none",
	} {
		r := s.MatchAny(name)
		got := "none"
		switch {
		case r.Excluded != "":
			got = "exclude"
		case r.Drop:
			got = "drop"
		case r.Session:
			got = "session"
		case r.Matched:
			got = "include"
		}
		if got != want {
			t.Errorf("%s: %s (%+v), want %s", name, got, r, want)
		}
	}
	// Session beats a plain rule for the same name.
	s2 := MustCompile([]string{"akamaized.net", "session:**.akamaized.net"})
	if r := s2.MatchAny("a.akamaized.net"); !r.Session {
		t.Errorf("plain rule won over session: %+v", r)
	}
	if !s.NeedsInspector() {
		t.Error("session rules need the inspector")
	}
	if b := strings.Join(s.Bases(), ","); !strings.Contains(b, "akamaized.net") {
		t.Errorf("bases %s", b)
	}
	if n := s.NativeSuffixes(); len(n) != 0 && strings.Contains(strings.Join(n, ","), "akamaized") {
		t.Errorf("session rule handed to dnsmasq: %v", n)
	}
	for _, bad := range []string{"session:", "!session:a.com", "session:asn:1", "session:drop:a.com", "drop:session:a.com", "session:!a.com"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
