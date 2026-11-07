package dnsinspect

import (
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
		Session: func(client string, addrs []string, rule, name string) error {
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
