package dnsinspect

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/system"
)

// An answer matching a session: rule starts a session for the device it
// goes to; nothing is added to the policy's sets or recorded.
func TestSessionAnswer(t *testing.T) {
	rec := &system.Recorder{}
	var got []string
	i := &Inspector{IPSet: netfilter.IPSet{R: rec}, CacheTTL: time.Hour}
	i.SetRules([]Rules{{ID: 1, Name: "p", Set: match.MustCompile([]string{"netflix.com", "session:**.akamaized.net"}), FollowCNAME: true, Set4: "SNK_1_d4",
		Session: func(client string, addrs []string, rule, name string, _ match.Opts) error {
			got = append(got, client+" "+strings.Join(addrs, ",")+" "+rule+" "+name)
			return nil
		}}})
	w := i.handle(answerPacket("a1.akamaized.net", net.IPv4(203, 0, 113, 80)))
	if w == nil {
		t.Fatal("no work: the answer would be released before the session exists")
	}
	if len(got) != 0 {
		t.Fatal("session started before the work ran")
	}
	w()
	if len(got) != 1 || got[0] != "192.168.50.10 203.0.113.80 session:**.akamaized.net a1.akamaized.net" {
		t.Fatalf("sessions %q", got)
	}
	if rec.Joined() != "" || len(i.AllRecords()) != 0 {
		t.Fatalf("session answer added to sets or recorded: %q", rec.Joined())
	}
	// A plain rule still goes to the set.
	if w := i.handle(answerPacket("www.netflix.com", net.IPv4(203, 0, 113, 1))); w != nil {
		w()
	}
	if !strings.Contains(rec.Joined(), "SNK_1_d4") && i.Stats().Added == 0 {
		t.Fatalf("plain answer not added: %q", rec.Joined())
	}
	if s := i.Stats(); s.Sessions != 1 || s.Matched != 2 {
		t.Fatalf("stats %+v", s)
	}
}

func TestRouteAnswer(t *testing.T) {
	rec := &system.Recorder{}
	var conds, routes []string
	act := ""
	i := &Inspector{IPSet: netfilter.IPSet{R: rec}, CacheTTL: time.Hour}
	i.SetRules([]Rules{{ID: 1, Name: "p", Set: match.MustCompile([]string{"if:and:(netflix.com, not:=help.netflix.com);then:route:**.akamaized.net"}), FollowCNAME: true, Set4: "SNK_1_d4",
		Cond: func(addrs []string, hits []match.CondHit) {
			conds = append(conds, fmt.Sprintf("%s %d", strings.Join(addrs, ","), hits[0].Atom))
		},
		Route: func(client string, addrs []string, rule, name, matched string) (string, error) {
			routes = append(routes, client+" "+strings.Join(addrs, ",")+" "+name+" "+matched)
			return act, nil
		}}})
	// if: name: recorded and routed like a plain rule.
	if w := i.handle(answerPacket("www.netflix.com", net.IPv4(198, 51, 100, 10))); w != nil {
		w()
	}
	// negated if: atom: recorded (atom 2) and routed by netflix.com.
	if w := i.handle(answerPacket("help.netflix.com", net.IPv4(198, 51, 100, 20))); w != nil {
		w()
	}
	if strings.Join(conds, "|") != "198.51.100.10 1|198.51.100.20 1" {
		t.Fatalf("conditions recorded %q", conds)
	}
	if !strings.Contains(rec.Joined(), "SNK_1_d4") && i.Stats().Added == 0 {
		t.Fatalf("if: answer not routed: %q", rec.Joined())
	}
	added := i.Stats().Added
	// route: name: the condition decides; never the set.
	w := i.handle(answerPacket("e1.akamaized.net", net.IPv4(203, 0, 113, 80)))
	if w == nil {
		t.Fatal("route answer released before the condition was checked")
	}
	w()
	if len(routes) != 1 || routes[0] != "192.168.50.10 203.0.113.80 e1.akamaized.net e1.akamaized.net" || i.Stats().Added != added {
		t.Fatalf("route %q, added %d -> %d", routes, added, i.Stats().Added)
	}
	// The branch's action is counted.
	dropped := i.Stats().Dropped
	act = match.ActDrop
	if w := i.handle(answerPacket("e2.akamaized.net", net.IPv4(203, 0, 113, 81))); w != nil {
		w()
	}
	if i.Stats().Dropped != dropped+1 || i.Stats().Added != added {
		t.Fatalf("drop branch: stats %+v", i.Stats())
	}
}

func TestDropSessionAnswer(t *testing.T) {
	rec := &system.Recorder{}
	var got []string
	i := &Inspector{IPSet: netfilter.IPSet{R: rec}, CacheTTL: time.Hour}
	i.SetRules([]Rules{{ID: 1, Name: "p", Set: match.MustCompile([]string{"drop[share=kids]:ads.example.com"}), Set4: "SNK_1_d4", DropSet4: "SNK_1_x4",
		DropSession: func(client string, addrs []string, rule, name string, opts match.Opts) error {
			got = append(got, client+" "+strings.Join(addrs, ",")+" "+strings.Join(opts.Share, ","))
			return nil
		}}})
	w := i.handle(answerPacket("x.ads.example.com", net.IPv4(203, 0, 113, 9)))
	if w == nil {
		t.Fatal("answer released before the block was in place")
	}
	w()
	if len(got) != 1 || got[0] != "192.168.50.10 203.0.113.9 kids" || strings.Contains(rec.Joined(), "SNK_1_x4") {
		t.Fatalf("drop session %q, sets %q", got, rec.Joined())
	}
}
