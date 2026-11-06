package match

import (
	"strings"
	"testing"
)

func TestParseAndMatch(t *testing.T) {
	cases := []struct {
		rule string
		kind Kind
		base string
		yes  []string
		no   []string
	}{
		{"Netflix.com", Suffix, "netflix.com", []string{"netflix.com", "www.netflix.com", "a.b.netflix.com"}, []string{"notnetflix.com", "netflix.com.evil"}},
		{"https://www.netflix.com/browse", Suffix, "www.netflix.com", []string{"www.netflix.com"}, []string{"netflix.com"}},
		{".example.com", Subdomains, "example.com", []string{"a.example.com", "a.b.example.com"}, []string{"example.com"}},
		{"=example.com", Exact, "example.com", []string{"example.com"}, []string{"a.example.com"}},
		{"*.example.com", Glob, "example.com", []string{"a.example.com", "x-1.example.com"}, []string{"a.b.example.com", "example.com"}},
		{"**.example.com", Glob, "example.com", []string{"a.example.com", "a.b.example.com"}, []string{"example.com", "aexample.com"}},
		{"api-?.*.disney.com", Glob, "disney.com", []string{"api-1.x.disney.com"}, []string{"api-12.x.disney.com", "api-1.disney.com"}},
		{"ipv4-*.oca.nflxvideo.net", Glob, "oca.nflxvideo.net", []string{"ipv4-c001-lhr.oca.nflxvideo.net"}, []string{"ipv6-c001.oca.nflxvideo.net"}},
		{"~nflx", Keyword, "", []string{"nflxvideo.net", "a.nflximg.com"}, []string{"netflix.com"}},
		{`/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/`, Regex, "oca.nflxvideo.net", []string{"ipv4-c123-lhr001-ix.oca.nflxvideo.net"}, []string{"ipv4-cx-lhr.oca.nflxvideo.net"}},
		{`re:disney`, Regex, "", []string{"disneyplus.com", "x.disney.api.edge"}, []string{"dssott.com"}},
		{`/(?:^|\.)bamgrid\.com$/`, Regex, "", []string{"bamgrid.com", "x.bamgrid.com"}, []string{"xbamgrid.com"}},
		{"*.net", Glob, "", []string{"a.net"}, nil},
		{"example.com # streaming", Suffix, "example.com", []string{"a.example.com"}, nil},
	}
	for _, c := range cases {
		p, err := Parse(c.rule)
		if err != nil {
			t.Errorf("%q: %v", c.rule, err)
			continue
		}
		if p.Kind != c.kind || p.Base != c.base {
			t.Errorf("%q: kind %s base %q, want %s %q", c.rule, p.Kind, p.Base, c.kind, c.base)
		}
		for _, n := range c.yes {
			if !p.Match(n) {
				t.Errorf("%q should match %q", c.rule, n)
			}
		}
		for _, n := range c.no {
			if p.Match(n) {
				t.Errorf("%q should not match %q", c.rule, n)
			}
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, r := range []string{"", "bad domain.com", "/unterminated", "/a(b/", "~", "=", "a***.com", "-bad-.com", ".", "!"} {
		if _, err := Parse(r); err == nil {
			t.Errorf("%q: expected error", r)
		}
	}
}

func TestSet(t *testing.T) {
	s, errs := Compile([]string{"# comment", "", "netflix.com", "**.nflxvideo.net", "!=ads.netflix.com", "bad rule"})
	if len(errs) != 1 || errs[0].Index != 5 {
		t.Fatalf("errs = %+v", errs)
	}
	if r := s.MatchAny("www.netflix.com"); !r.Matched || r.Rule != "netflix.com" {
		t.Fatalf("%+v", r)
	}
	if r := s.MatchAny("ads.netflix.com"); r.Matched || r.Excluded != "!=ads.netflix.com" {
		t.Fatalf("exclusion: %+v", r)
	}
	// CNAME chain: query name unknown, target matches.
	if r := s.MatchAny("movies.partner.tv", "abc.lhr.nflxvideo.net"); !r.Matched || r.Name != "abc.lhr.nflxvideo.net" {
		t.Fatalf("cname: %+v", r)
	}
	if s.NativeSuffixes() != nil || !s.NeedsInspector() {
		t.Fatal("exclusions must disable the dnsmasq fast path")
	}
	plain, _ := Compile([]string{"netflix.com", "nflxvideo.net"})
	if len(plain.NativeSuffixes()) != 2 || plain.NeedsInspector() {
		t.Fatal("plain suffixes should be native")
	}
	if b := s.Bases(); len(b) != 2 || b[0] != "netflix.com" || b[1] != "nflxvideo.net" {
		t.Fatalf("bases = %v", b)
	}
}

func TestRegexErrorText(t *testing.T) {
	_, err := Parse("/bad(regex/")
	if err == nil || strings.Contains(err.Error(), "(?i)") {
		t.Fatalf("error = %v", err)
	}
}
