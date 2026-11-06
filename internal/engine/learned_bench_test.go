package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/dnsinspect"
)

func BenchmarkLearnedAddrs50k(b *testing.B) {
	e, rec := learnEngine(b)
	var sb strings.Builder
	sb.WriteString("Name: SNK_1_d4\nMembers:\n")
	var recs []dnsinspect.Record
	now := time.Now()
	for i := 0; i < 50000; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)
		fmt.Fprintf(&sb, "%s timeout 3000\n", ip)
		if i%2 == 0 {
			recs = append(recs, dnsinspect.Record{Set: "SNK_1_d4", Addr: ip, Name: fmt.Sprintf("h%d.netflix.com", i), Rule: "netflix.com", Client: "192.168.50.2", LastSeen: now.Add(-time.Duration(i) * time.Second)})
		}
	}
	rec.Responses = map[string]string{"ipset list SNK_1_d4": sb.String()}
	e.dns.LoadRecords(recs)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if v, _ := e.LearnedAddrs("1", "dns", "", 0); v.Total != 50000 {
			b.Fatal(v.Total)
		}
	}
}
