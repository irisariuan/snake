package webrtc

import (
	"sort"
	"strings"
	"testing"

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

func TestRefreshServerTTL(t *testing.T) {
	f := &fakeIPSet{
		members: map[string][]string{
			"SNK_1_t4": {"203.0.113.7 timeout 120", "198.51.100.9 timeout 80000"},
			"SNK_1_t6": {"2001:db8::1 timeout 500"},
		},
		added: map[string][]string{},
	}
	tr := NewTracker(netfilter.IPSet{R: f}, 0xff0000)
	conntrack := strings.Join([]string{
		// live call to a learned server: re-armed
		"ipv4 2 udp 17 170 src=192.168.50.10 dst=203.0.113.7 sport=50000 dport=3478 src=203.0.113.7 dst=10.2.0.2 sport=3478 dport=50000 [ASSURED] mark=65536 use=1",
		// policy-marked but not a learned server: session only
		"ipv4 2 tcp 6 7000 ESTABLISHED src=192.168.50.11 dst=52.1.2.3 sport=51234 dport=443 src=52.1.2.3 dst=10.2.0.2 sport=443 dport=51234 [ASSURED] mark=65536 use=1",
		// learned server of policy 1, but the flow is unmarked (WAN): not ours
		"ipv4 2 udp 17 20 src=192.168.50.12 dst=198.51.100.9 sport=5000 dport=3478 src=198.51.100.9 dst=1.2.3.4 sport=3478 dport=5000 mark=0 use=1",
		// IPv6 in procfs full form
		"ipv6 10 udp 17 170 src=2001:0db8:0000:0000:0000:0000:0000:0010 dst=2001:0db8:0000:0000:0000:0000:0000:0001 sport=50000 dport=3478 src=2001:0db8:0000:0000:0000:0000:0000:0001 dst=2001:0db8:0000:0000:0000:0000:0000:0010 sport=3478 dport=50000 mark=65536 use=1",
	}, "\n")
	tr.refreshFrom(strings.NewReader(conntrack), map[int]bool{1: true}, 16)
	got := func(set string) string {
		l := append([]string(nil), f.added[set]...)
		sort.Strings(l)
		return strings.Join(l, ",")
	}
	if g := got("SNK_1_t4"); g != "203.0.113.7" {
		t.Errorf("server refresh v4 = %q (idle 198.51.100.9 must keep counting down)", g)
	}
	if g := got("SNK_1_t6"); g != "2001:db8::1" {
		t.Errorf("server refresh v6 = %q", g)
	}
	if g := got("SNK_1_s4"); g != "192.168.50.10,192.168.50.11" {
		t.Errorf("sessions = %q", g)
	}
}

func TestCountLearned(t *testing.T) {
	tr := NewTracker(netfilter.IPSet{R: &fakeIPSet{added: map[string][]string{}}}, 0xff0000)
	tr.stats[12] = &Stats{}
	tr.countLearned(netfilter.SetName(12, netfilter.KindServer, false), 2)
	tr.countLearned(netfilter.SetName(12, netfilter.KindPeer, true), 3)
	if s := tr.Stats()[12]; s.Servers != 2 || s.Learned != 3 {
		t.Fatalf("stats %+v", s)
	}
}
