package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/dnsinspect"
)

func TestLearnedDNSAddrs(t *testing.T) {
	e, rec := learnEngine(t)
	now := time.Now()
	e.dns.LoadRecords([]dnsinspect.Record{
		{Set: "SNK_1_d4", Addr: "54.155.178.5", Name: "www.netflix.com", Matched: "www.netflix.com", Rule: "netflix.com", Client: "192.168.50.23", FirstSeen: now.Add(-time.Hour), LastSeen: now, Hits: 3},
		{Set: "SNK_1_d4", Addr: "23.246.50.141", Name: "play.partner.tv", Matched: "x1.cdn.nflxvideo.net", Rule: "**.nflxvideo.net", Client: "192.168.50.23", FirstSeen: now, LastSeen: now.Add(-time.Minute), Hits: 1},
		{Set: "SNK_2_d4", Addr: "34.120.10.2", Name: "disneyplus.com", Rule: "disneyplus.com", LastSeen: now},
	})
	rec.Responses = map[string]string{
		"ipset list SNK_1_d4": "Name: SNK_1_d4\nMembers:\n54.155.178.5\n23.246.50.141\n203.0.113.99\n",
	}
	v, err := e.LearnedAddrs("Netflix US", "dns", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.PolicyID != 1 || v.Total != 3 || v.Unknown != 1 || len(v.Addrs) != 3 {
		t.Fatalf("%+v", v)
	}
	if a := v.Addrs[0]; a.Addr != "54.155.178.5" || a.Rule != "netflix.com" || a.Source != "policy" || a.Matched != "" || a.Hits != 3 {
		t.Fatalf("first %+v", a)
	}
	if a := v.Addrs[1]; a.Matched != "x1.cdn.nflxvideo.net" {
		t.Fatalf("cname %+v", a)
	}
	if a := v.Addrs[2]; a.Addr != "203.0.113.99" || a.LastSeen != nil {
		t.Fatalf("unknown last %+v", a)
	}
	if len(v.Rules) != 3 {
		t.Fatalf("rules %+v", v.Rules)
	}
	if f, _ := e.LearnedAddrs("1", "dns", "nflxvideo", 0); f.Matching != 1 || f.Addrs[0].Addr != "23.246.50.141" {
		t.Fatalf("filter %+v", f)
	}
	if _, err := e.LearnedAddrs("nope", "dns", "", 0); err == nil {
		t.Fatal("unknown policy accepted")
	}

	// forget by rule: ipset del + record and cache dropped
	rule := "**.nflxvideo.net"
	n, err := e.ForgetLearned("1", ForgetRequest{Kind: "dns", Rule: &rule})
	if err != nil || n != 1 {
		t.Fatalf("forget rule: %d %v", n, err)
	}
	last := rec.Commands[len(rec.Commands)-1]
	if !strings.Contains(last, "del SNK_1_d4 23.246.50.141") || strings.Contains(last, "54.155.178.5") {
		t.Fatalf("del command: %s", last)
	}
	if _, ok := e.dns.Records("SNK_1_d4")["23.246.50.141"]; ok {
		t.Fatal("record not forgotten")
	}
	// forget all of a policy leaves other policies alone
	if _, err := e.ForgetLearned("1", ForgetRequest{Kind: "dns", All: true}); err != nil {
		t.Fatal(err)
	}
	if len(e.dns.Records("SNK_1_d4")) != 0 || len(e.dns.Records("SNK_2_d4")) != 1 {
		t.Fatal("flush scope wrong")
	}
	if _, err := e.ForgetLearned("1", ForgetRequest{Kind: "peer", Rule: &rule}); err == nil {
		t.Fatal("rule on peers accepted")
	}
}
