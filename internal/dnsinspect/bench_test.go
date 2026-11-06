package dnsinspect

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/system"
)

// answerPacket builds an IPv4/UDP packet carrying a DNS A answer.
func answerPacket(name string, ip net.IP) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	_ = b.StartQuestions()
	n := dnsmessage.MustNewName(name + ".")
	_ = b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	var a [4]byte
	copy(a[:], ip.To4())
	_ = b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: a})
	msg, _ := b.Finish()
	h := make([]byte, 28)
	h[0] = 0x45
	h[9] = 17
	copy(h[12:16], []byte{192, 168, 50, 1})
	copy(h[16:20], []byte{192, 168, 50, 10})
	binary.BigEndian.PutUint16(h[20:22], 53)
	binary.BigEndian.PutUint16(h[22:24], 40000)
	binary.BigEndian.PutUint16(h[2:4], uint16(28+len(msg)))
	return append(h, msg...)
}

func benchInspector() *Inspector {
	rules := []string{"match.example", "**.akamai.example", `/^ipv4-c\d+-x\.example$/`, "~zzkeyword"}
	for i := 0; i < 20000; i++ {
		rules = append(rules, fmt.Sprintf("dom%d.example", i))
	}
	i := &Inspector{IPSet: netfilter.IPSet{R: &system.Recorder{}}, CacheTTL: time.Hour}
	i.SetRules([]Rules{{ID: 1, Name: "big", Set: match.MustCompile(rules), FollowCNAME: true, Set4: "SNK_1_d4"}})
	return i
}

func BenchmarkHandleNoMatch(b *testing.B) {
	i := benchInspector()
	pk := answerPacket("www.unrouted-site.com", net.IPv4(198, 51, 100, 1))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if w := i.handle(pk); w != nil {
			b.Fatal("work for a non-matching answer")
		}
	}
}

func BenchmarkHandleMatchNew(b *testing.B) {
	i := benchInspector()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pk := answerPacket(fmt.Sprintf("q%d.match.example", n), net.IPv4(10, byte(n>>16), byte(n>>8), byte(n)))
		if w := i.handle(pk); w != nil {
			w()
		}
	}
}
