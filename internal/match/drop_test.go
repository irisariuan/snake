package match

import "testing"

func TestDropRules(t *testing.T) {
	for in, want := range map[string]string{
		"DROP:Ads.Example.com":      "drop:ads.example.com",
		"drop: https://x.example/a": "drop:x.example",
		"drop:ASN:AS1234":           "drop:asn:1234",
		"drop:CIDR: 10.0.0.0/8":     "drop:cidr:10.0.0.0/8",
		"drop:/^AD-\\d+\\.x$/":      "drop:/^AD-\\d+\\.x$/",
		"drop:ads.example.com # c":  "drop:ads.example.com",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"drop:", "!drop:ads.example.com", "drop:!ads.example.com", "drop:drop:a.example", "drop:asn:x", "drop:cidr:1.2.3", "drop:com"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	p, err := Parse("drop:asn:AS1234")
	if err != nil || p.Kind != ASN || p.Value != "1234" || !p.Drop {
		t.Fatalf("asn: %+v %v", p, err)
	}
	p, err = Parse("drop:ip:192.0.2.9")
	if err != nil || p.Kind != CIDR || p.Value != "192.0.2.9" {
		t.Fatalf("ip: %+v %v", p, err)
	}

	s := MustCompile([]string{
		"example.com", "**.cdn.example", "drop:ads.example.com", "drop:**.tracker.example", "drop:~doubleclk",
		"!=ok.ads.example.com", "drop:asn:1234", "drop:cidr:198.51.100.0/24", "drop:cidr:203.0.113.7",
	})
	if len(s.Include) != 2 || len(s.Drop) != 3 || len(s.Exclude) != 1 || len(s.DropASNs) != 1 || len(s.DropCIDRs) != 2 || !s.HasDrops() {
		t.Fatalf("compiled %+v", s)
	}
	cases := []struct {
		names         []string
		matched, drop bool
		rule          string
	}{
		{[]string{"www.example.com"}, true, false, "example.com"},
		{[]string{"ads.example.com"}, true, true, "drop:ads.example.com"},   // drop beats the include
		{[]string{"x.ads.example.com"}, true, true, "drop:ads.example.com"}, // subdomain
		{[]string{"ok.ads.example.com"}, false, false, ""},                  // ! exempts from drop
		{[]string{"a.b.tracker.example"}, true, true, "drop:**.tracker.example"},
		{[]string{"www.example.com", "ad.doubleclk.net"}, true, true, "drop:~doubleclk"}, // via CNAME
		{[]string{"unrelated.test"}, false, false, ""},
	}
	for _, c := range cases {
		r := s.MatchAny(c.names...)
		if r.Matched != c.matched || r.Drop != c.drop || r.Rule != c.rule {
			t.Errorf("%v: %+v", c.names, r)
		}
	}
	if got := s.DropSuffixes(false); got != nil {
		t.Errorf("with exclusions dnsmasq must not drop by itself: %v", got)
	}
	if got := s.DropSuffixes(true); len(got) != 1 || got[0] != "ads.example.com" {
		t.Errorf("degraded drop suffixes %v", got)
	}
	if !s.NeedsInspector() {
		t.Error("drop wildcards need the inspector")
	}
	plain := MustCompile([]string{"drop:ads.example.com"})
	if plain.NeedsInspector() || len(plain.DropSuffixes(false)) != 1 || len(plain.NativeSuffixes()) != 0 {
		t.Errorf("plain drop: inspector=%v drop=%v native=%v", plain.NeedsInspector(), plain.DropSuffixes(false), plain.NativeSuffixes())
	}
}
