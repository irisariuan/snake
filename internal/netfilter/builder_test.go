package netfilter

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
)

func states(t *testing.T) (*config.Config, []PolicyState) {
	b, err := os.ReadFile("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	c := config.Default()
	if err := json.Unmarshal(b, c); err != nil {
		t.Fatal(err)
	}
	c.ApplyDefaults()
	c.Normalize()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c, []PolicyState{
		{Policy: c.Policies[0], ActiveTunnel: "wgc1", IPv6Mode: V6Route, WebRTCMode: RTCQueue},
		{Policy: c.Policies[1], MACs: c.ResolveDevices(c.Policies[1]), ActiveTunnel: "wgc2", IPv6Mode: V6Block, WebRTCMode: RTCPorts},
		{Policy: c.Policies[2], MACs: c.ResolveDevices(c.Policies[2]), ActiveTunnel: "", IPv6Mode: V6Off, WebRTCMode: RTCOff},
	}
}

func mustContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, x := range subs {
		if !strings.Contains(s, x) {
			t.Errorf("missing %q in:\n%s", x, s)
		}
	}
}

func TestBuild(t *testing.T) {
	c, st := states(t)
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true, Existing: map[string][]string{"4/mangle": {"SNAKE", "SNAKE_P9", "SNAKE_M9"}}})
	m4 := plan.Restore["4/mangle"]
	mustContain(t, m4,
		"-A SNAKE -m mark --mark 0/0xff0000 -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000",
		"-A SNAKE -m mark ! --mark 0/0xff0000 -g SNAKE_SAVE",
		"-A SNAKE_M1 -j MARK --set-xmark 0x10000/0xff0000",
		"-A SNAKE_P1 -m set --match-set SNK_1_d4 dst -g SNAKE_M1",
		"-A SNAKE_P1 -m set --match-set SNK_1_n4 dst -g SNAKE_M1",
		// session refresh + learned peers + nfqueue
		"-m conntrack --ctstate NEW -m set --match-set SNK_1_d4 dst -j SET --add-set SNK_1_s4 src --exist",
		"-A SNAKE_P1 -p udp -m set --match-set SNK_1_s4 src -m set --match-set SNK_1_r4 dst -g SNAKE_M1",
		"-A SNAKE_RTC -p udp -m conntrack --ctstate NEW -m set --match-set SNK_1_s4 src -j NFQUEUE --queue-num 4201 --queue-bypass",
		// learned STUN servers: routed outside sessions and open the window
		"-A SNAKE_P1 -p udp -m set --match-set SNK_1_t4 dst -g SNAKE_M1",
		"-A SNAKE -p udp -m conntrack --ctstate NEW -m set --match-set SNK_1_t4 dst -j SET --add-set SNK_1_s4 src --exist",
		// device + destination
		"-A SNAKE_P2 -m mac --mac-source aa:bb:cc:00:00:01 -m set --match-set SNK_2_d4 dst -g SNAKE_M2",
		"-A SNAKE_P2 -p udp -m multiport --dports 3478,3479,5349,19302:19309 -m set --match-set SNK_2_s4 src -g SNAKE_M2",
		// whole device
		"-A SNAKE_P3 -m mac --mac-source aa:bb:cc:00:00:09 -g SNAKE_M3",
		"-A SNAKE_MSS -o tun12 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		// stale chains deleted
		"-X SNAKE_M9", "-X SNAKE_P9",
	)
	if strings.Contains(m4, "SNK_2_t4") {
		t.Error("server set used in ports fallback mode")
	}
	if strings.Contains(m4, "-X SNAKE\n") {
		t.Error("live chain deleted")
	}
	// policy order: P1 before P2 before P3, RTC last
	i1, i2, i3, ir := strings.Index(m4, "-A SNAKE -j SNAKE_P1"), strings.Index(m4, "-A SNAKE -j SNAKE_P2"), strings.Index(m4, "-A SNAKE -j SNAKE_P3"), strings.Index(m4, "-A SNAKE -j SNAKE_RTC")
	if !(i1 >= 0 && i1 < i2 && i2 < i3 && i3 < ir) {
		t.Errorf("policy order wrong: %d %d %d %d", i1, i2, i3, ir)
	}
	n4 := plan.Restore["4/nat"]
	// policies 1 (global) and 2 (devices) both hijack: global wins, no per-mac duplicates
	mustContain(t, n4, "-A SNAKE_DNS -i br+ -p udp --dport 53 -j REDIRECT --to-ports 53", "-A SNAKE_NAT -o wgc1 -m mark ! --mark 0/0xff0000 -j MASQUERADE")
	if strings.Contains(n4, "--mac-source") {
		t.Error("global DNS hijack should not need per-MAC rules")
	}
	f4 := plan.Restore["4/filter"]
	mustContain(t, f4,
		"-A SNAKE_FWD -i br+ -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -i br+ -p tcp --dport 443 -m set --match-set SNK_DOH4 dst -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -i br+ -m mac --mac-source aa:bb:cc:00:00:09 -p udp --dport 443 -j REJECT",
		"-A SNAKE_FWD -i br+ -o wgc1 -m mark ! --mark 0/0xff0000 -j ACCEPT",
	)
	// leak blocks must precede accepts
	if strings.Index(f4, "--dport 853") > strings.Index(f4, "-j ACCEPT") {
		t.Error("blocks after accepts")
	}
	m6, f6 := plan.Restore["6/mangle"], plan.Restore["6/filter"]
	mustContain(t, m6, "SNK_1_d6", "-d ::1/128,fc00::/7,fe80::/10,ff00::/8 -j RETURN")
	if strings.Contains(m6, "SNAKE_P3") {
		t.Error("ipv6 off policy present in v6 rules")
	}
	mustContain(t, f6, "-A SNAKE_FWD -m mark --mark 0x20000/0xff0000 -j REJECT --reject-with icmp6-adm-prohibited", "icmp6-port-unreachable")
	if strings.Contains(m4, "NFQUEUE --queue-num 4200") {
		t.Error("DNS queue rule without DNSQueue option")
	}
	if len(plan.Hooks) != 12 {
		t.Errorf("hooks = %d", len(plan.Hooks))
	}
}

func TestBuildNoIPv6NAT(t *testing.T) {
	c, st := states(t)
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: false})
	if _, ok := plan.Restore["6/nat"]; ok {
		t.Error("6/nat generated without ipv6 nat support")
	}
	for _, h := range plan.Hooks {
		if h.V6 && h.Table == "nat" {
			t.Error("v6 nat hook without support")
		}
	}
}

func TestSetNamesFit(t *testing.T) {
	if n := SetName(200, KindSession, true); len(n) > 31 {
		t.Fatal(n)
	}
}

func TestBuildDNSInspector(t *testing.T) {
	c, st := states(t)
	plan := Build(c.Settings, st, Options{DNSQueue: 4200})
	mustContain(t, plan.Restore["4/mangle"],
		"-A SNAKE_DNSO -o br+ -j NFQUEUE --queue-num 4200 --queue-bypass",
		"-A SNAKE_DNSO -o lo -j NFQUEUE --queue-num 4200 --queue-bypass")
	found := false
	for _, h := range plan.Hooks {
		if h.Table == "mangle" && h.Chain == "OUTPUT" && strings.Join(h.Args, " ") == "-p udp --sport 53 -j SNAKE_DNSO" {
			found = true
		}
	}
	if !found {
		t.Error("OUTPUT hook missing")
	}
}

func TestBuildServerSetPerDevice(t *testing.T) {
	c, st := states(t)
	st[1].WebRTCMode = RTCQueue // device + destination policy
	m4 := Build(c.Settings, st, Options{}).Restore["4/mangle"]
	mustContain(t, m4,
		"-A SNAKE_P2 -m mac --mac-source aa:bb:cc:00:00:01 -p udp -m set --match-set SNK_2_t4 dst -g SNAKE_M2",
		"-A SNAKE -m mac --mac-source aa:bb:cc:00:00:01 -p udp -m conntrack --ctstate NEW -m set --match-set SNK_2_t4 dst -j SET --add-set SNK_2_s4 src --exist",
	)
	if strings.Contains(m4, "-A SNAKE_P2 -p udp -m set --match-set SNK_2_t4") {
		t.Error("device policy's server set applied LAN-wide")
	}
}
