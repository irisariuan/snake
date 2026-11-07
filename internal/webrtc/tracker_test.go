package webrtc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/netfilter"
)

// fakeIPSet answers `ipset list` from fixed members and records adds.
type fakeIPSet struct {
	members map[string][]string
	added   map[string][]string
}

func (f *fakeIPSet) Run(name string, args ...string) (string, error) {
	if name == "ipset" && len(args) == 2 && args[0] == "list" {
		m, ok := f.members[args[1]]
		if !ok {
			return "", errNoSet
		}
		return "Name: " + args[1] + "\nMembers:\n" + strings.Join(m, "\n") + "\n", nil
	}
	return "", nil
}

func (f *fakeIPSet) RunInput(in, name string, args ...string) (string, error) {
	for _, l := range strings.Split(strings.TrimSpace(in), "\n") {
		p := strings.Fields(l)
		if len(p) == 3 && p[0] == "add" {
			f.added[p[1]] = append(f.added[p[1]], p[2])
		}
	}
	return "", nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errNoSet = errString("no such set")

func TestRefreshScan(t *testing.T) {
	f := &fakeIPSet{members: map[string][]string{}, added: map[string][]string{}}
	tr := NewTracker(netfilter.IPSet{R: f}, 0xff0000)
	known := map[string]int{"203.0.113.7": 1, "198.51.100.9": 0, "2001:db8::1": 1, "192.0.2.50": 2}
	tr.ServerRoute = func(a string) (int, bool) { p, ok := known[a]; return p, ok }
	var got Scan
	tr.OnScan = func(s Scan) { got = s }
	conntrack := strings.Join([]string{
		// live call to a learned server through the tunnel
		"ipv4 2 udp 17 170 src=192.168.50.10 dst=203.0.113.7 sport=50000 dport=3478 src=203.0.113.7 dst=10.2.0.2 sport=3478 dport=50000 [ASSURED] mark=65536 use=1",
		// policy-marked, not a learned server: session only
		"ipv4 2 tcp 6 7000 ESTABLISHED src=192.168.50.11 dst=52.1.2.3 sport=51234 dport=443 src=52.1.2.3 dst=10.2.0.2 sport=443 dport=51234 [ASSURED] mark=65536 use=1",
		// learned server of a group sent to WAN: unmarked, still activity
		"ipv4 2 udp 17 20 src=192.168.50.12 dst=198.51.100.9 sport=5000 dport=3478 src=198.51.100.9 dst=1.2.3.4 sport=3478 dport=5000 mark=0 use=1",
		// closing TCP to a learned server: not activity
		"ipv4 2 tcp 6 10 TIME_WAIT src=192.168.50.12 dst=192.0.2.50 sport=5001 dport=443 src=192.0.2.50 dst=1.2.3.4 sport=443 dport=5001 mark=131072 use=1",
		// IPv6 in procfs full form
		"ipv6 10 udp 17 170 src=2001:0db8:0000:0000:0000:0000:0000:0010 dst=2001:0db8:0000:0000:0000:0000:0000:0001 sport=50000 dport=3478 src=2001:0db8:0000:0000:0000:0000:0000:0001 dst=2001:0db8:0000:0000:0000:0000:0000:0010 sport=3478 dport=50000 mark=65536 use=1",
	}, "\n")
	tr.refreshFrom(strings.NewReader(conntrack), map[int]bool{1: true, 2: true}, 16)
	keys := func(m map[string]bool) string {
		var l []string
		for k := range m {
			l = append(l, k)
		}
		sort.Strings(l)
		return strings.Join(l, ",")
	}
	if g := keys(got.Active); g != "198.51.100.9,2001:db8::1,203.0.113.7" {
		t.Errorf("active = %q", g)
	}
	if len(got.Sessions) != 3 || !got.Sessions[SessionKey{1, "192.168.50.10"}] || !got.Sessions[SessionKey{1, "2001:db8::10"}] || got.Sessions[SessionKey{2, "192.168.50.12"}] {
		t.Errorf("sessions = %v", got.Sessions)
	}
	l := append([]string(nil), f.added["SNK_1_s4"]...)
	sort.Strings(l)
	if g := strings.Join(l, ","); g != "192.168.50.10,192.168.50.11" {
		t.Errorf("session set = %q", g)
	}
}

func TestPolicyMark(t *testing.T) {
	tr := NewTracker(netfilter.IPSet{}, 0xff0000)
	if m := tr.policyMark(3); m != 0x30000 {
		t.Fatalf("mark %x", m)
	}
}

// Peers a client's STUN revealed become sessions of that client: they
// are batched per client and handed to OnPeer.
func TestLearnerHandsPeersToSessions(t *testing.T) {
	tr := NewTracker(netfilter.IPSet{}, 0xff0000)
	tr.stats[12] = &Stats{}
	tr.learnCh = make(chan learnReq, 10)
	var mu sync.Mutex
	got := map[string]string{}
	tr.OnPeer = func(policy int, client string, peers []string) error {
		mu.Lock()
		defer mu.Unlock()
		got[fmt.Sprintf("%d %s", policy, client)] = strings.Join(peers, ",")
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	tr.wg.Add(1)
	go tr.learner(ctx)
	for _, r := range []learnReq{{12, "192.168.50.23", "203.0.113.9"}, {12, "192.168.50.23", "198.51.100.4"}, {12, "192.168.50.23", "203.0.113.9"}, {12, "192.168.50.40", "203.0.113.9"}} {
		tr.learnCh <- r
	}
	time.Sleep(400 * time.Millisecond)
	cancel()
	tr.wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if got["12 192.168.50.23"] != "198.51.100.4,203.0.113.9" || got["12 192.168.50.40"] != "203.0.113.9" || len(got) != 2 {
		t.Fatalf("sessions %v", got)
	}
	if s := tr.Stats()[12]; s.Learned != 3 {
		t.Fatalf("stats %+v", s)
	}
}
