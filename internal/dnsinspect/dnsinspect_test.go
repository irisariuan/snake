package dnsinspect

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/irisariuan/snake/internal/match"
)

// BuildAnswer builds a DNS response with an optional CNAME chain.
func BuildAnswer(t *testing.T, q string, chain []string, ips ...string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RecursionAvailable: true})
	b.EnableCompression()
	qn := dnsmessage.MustNewName(q + ".")
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: qn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	owner := qn
	for _, c := range chain {
		cn := dnsmessage.MustNewName(c + ".")
		_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.CNAMEResource{CNAME: cn})
		owner = cn
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		h := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 60}
		if v4 := ip.To4(); v4 != nil {
			var a [4]byte
			copy(a[:], v4)
			_ = b.AResource(h, dnsmessage.AResource{A: a})
		} else {
			var a [16]byte
			copy(a[:], ip)
			_ = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a})
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestParseAnswer(t *testing.T) {
	msg := BuildAnswer(t, "WWW.Netflix.com", []string{"www.dradis.netflix.com", "edge.akamaized.net"}, "203.0.113.1", "2001:db8::1")
	a, ok := ParseAnswer(msg)
	if !ok || a.Question != "www.netflix.com" || len(a.Chain) != 2 || a.Chain[1] != "edge.akamaized.net" || len(a.IPs) != 2 {
		t.Fatalf("%+v %v", a, ok)
	}
	if _, ok := ParseAnswer(msg[:10]); ok {
		t.Fatal("truncated message accepted")
	}
}

func TestDecide(t *testing.T) {
	rules := []Rules{
		{ID: 1, Name: "nf", Set: match.MustCompile([]string{"netflix.com", "!=ads.netflix.com"}), FollowCNAME: true},
		{ID: 2, Name: "cdn", Set: match.MustCompile([]string{"**.akamaized.net"}), FollowCNAME: true},
		{ID: 3, Name: "strict", Set: match.MustCompile([]string{"~partner"}), FollowCNAME: false},
	}
	cases := []struct {
		q     string
		chain []string
		want  int
	}{
		{"www.netflix.com", nil, 1},
		{"ads.netflix.com", nil, 0},
		{"ads.netflix.com", []string{"x.akamaized.net"}, 2}, // excluded from 1, matched by 2 via CNAME
		{"tv.partner.com", []string{"x.akamaized.net"}, 2},  // policy order: 2 before 3
		{"tv.partner.com", []string{"y.unrelated.net"}, 3},
		{"other.com", []string{"tv.partner.com"}, 0}, // 3 does not follow CNAMEs
	}
	for _, c := range cases {
		r, _, ok := Decide(rules, Answer{Question: c.q, Chain: c.chain})
		got := 0
		if ok {
			got = r.ID
		}
		if got != c.want {
			t.Errorf("%s %v: policy %d, want %d", c.q, c.chain, got, c.want)
		}
	}
}
