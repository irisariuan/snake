package match

import (
	"fmt"
	"reflect"
	"testing"
)

// linear is the reference: first name, earliest rule.
func linear(s *Set, names ...string) Result {
	for _, n := range names {
		for _, p := range s.Exclude {
			if p.Match(n) {
				return Result{Excluded: p.Raw, Name: n}
			}
		}
	}
	for _, n := range names {
		for _, p := range s.Include {
			if p.Match(n) {
				return Result{Matched: true, Name: n, Rule: p.Raw}
			}
		}
	}
	return Result{}
}

func TestIndexMatchesLinear(t *testing.T) {
	rules := []string{
		"~flix", "netflix.com", ".netflix.com", "=www.netflix.com", "*.nflxvideo.net", "**.nflxvideo.net",
		"nflxvideo.net", "/^ipv4-c\\d+-.*\\.oca\\.nflxvideo\\.net$/", "=example.org", ".example.org", "example.org",
		"cdn-?.example.net", "com", "!=ads.netflix.com", "!.tracking.example.org", "!~adserver",
	}
	names := []string{
		"netflix.com", "www.netflix.com", "a.b.netflix.com", "ads.netflix.com", "x.ads.netflix.com",
		"nflxvideo.net", "a.nflxvideo.net", "a.b.nflxvideo.net", "ipv4-c042-lhr001.oca.nflxvideo.net",
		"example.org", "www.example.org", "t.tracking.example.org", "cdn-1.example.net", "cdn-12.example.net",
		"anything.com", "com", "adserver.example.org", "unrelated.test", "", "netflix.com.evil.test", "xnetflix.com",
	}
	s := MustCompile(rules)
	// every name alone, and as chains
	for _, a := range names {
		if got, want := s.MatchAny(a), linear(s, a); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %+v want %+v", a, got, want)
		}
		for _, b := range names[:6] {
			if got, want := s.MatchAny(a, b), linear(s, a, b); !reflect.DeepEqual(got, want) {
				t.Errorf("%q,%q: got %+v want %+v", a, b, got, want)
			}
		}
	}
	// rule order decides which rule is reported
	for i := range rules {
		rot := append(append([]string{}, rules[i:]...), rules[:i]...)
		r := MustCompile(rot)
		for _, n := range names {
			if got, want := r.MatchAny(n), linear(r, n); !reflect.DeepEqual(got, want) {
				t.Errorf("rotation %d %q: got %+v want %+v", i, n, got, want)
			}
		}
	}
}

func bigSet(n int) *Set {
	rules := []string{"**.akamai.example", `/^ipv4-c\d+-x\.example$/`, "~zzkeyword"}
	for i := 0; i < n; i++ {
		rules = append(rules, fmt.Sprintf("dom%d.example", i))
	}
	return MustCompile(rules)
}

func BenchmarkMatchNoHit20k(b *testing.B) {
	s := bigSet(20000)
	for i := 0; i < b.N; i++ {
		s.MatchAny("www.some-unrouted-site.com", "edge.cdn.provider.net")
	}
}

func BenchmarkLinearNoHit20k(b *testing.B) {
	s := bigSet(20000)
	for i := 0; i < b.N; i++ {
		linear(s, "www.some-unrouted-site.com", "edge.cdn.provider.net")
	}
}
