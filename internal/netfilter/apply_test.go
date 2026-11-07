package netfilter

import (
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/system"
)

func hasCmd(r *system.Recorder, cmd string) bool {
	for _, c := range r.Commands {
		if c == cmd {
			return true
		}
	}
	return false
}

func TestApplyRemovesHooksOfDroppedInterfaces(t *testing.T) {
	rec := &system.Recorder{Responses: map[string]string{
		"iptables -t mangle -S PREROUTING": "-P PREROUTING ACCEPT\n-A PREROUTING -i br0 -j SNAKE\n-A PREROUTING -i br+ -j SNAKE\n-A PREROUTING -i br0 -j OTHER\n",
		"iptables -t nat -S PREROUTING":    "-P PREROUTING ACCEPT\n-A PREROUTING -i wgs+ -j SNAKE_DNS\n-A PREROUTING -i br+ -j SNAKE_DNS\n",
	}}
	plan := Plan{Hooks: []Hook{
		{Table: "mangle", Chain: "PREROUTING", Args: []string{"-i", "br+", "-j", ChainMain}},
		{Table: "nat", Chain: "PREROUTING", Args: []string{"-i", "br+", "-j", ChainDNS}},
	}}
	if err := (Applier{R: rec}).Apply(plan); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -t mangle -D PREROUTING -i br0 -j SNAKE",
		"iptables -t nat -D PREROUTING -i wgs+ -j SNAKE_DNS",
	} {
		if !hasCmd(rec, want) {
			t.Errorf("missing %q in %v", want, rec.Commands)
		}
	}
	for _, keep := range []string{"-D PREROUTING -i br+", "-j OTHER"} {
		for _, c := range rec.Commands {
			if strings.Contains(c, keep) && strings.Contains(c, " -D ") {
				t.Errorf("removed a hook it should keep: %s", c)
			}
		}
	}
}

func TestTeardownRemovesEveryInterfaceHook(t *testing.T) {
	rec := &system.Recorder{Responses: map[string]string{
		"iptables -t mangle -S PREROUTING": "-A PREROUTING -i tun21 -j SNAKE\n",
	}}
	(Applier{R: rec}).Teardown(false, "br+")
	if !hasCmd(rec, "iptables -t mangle -D PREROUTING -i tun21 -j SNAKE") {
		t.Errorf("hook of an unlisted interface left behind: %v", rec.Commands)
	}
}
