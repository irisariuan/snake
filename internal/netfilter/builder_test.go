package netfilter

import (
	"encoding/json"
	"os"
	"regexp"
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
		{Policy: c.Policies[1], Clients: c.ResolveDevices(c.Policies[1]), ActiveTunnel: "wgc2", IPv6Mode: V6Block, WebRTCMode: RTCPorts},
		{Policy: c.Policies[2], Clients: c.ResolveDevices(c.Policies[2]), ActiveTunnel: "", IPv6Mode: V6Off, WebRTCMode: RTCOff},
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
		"-A SNAKE -m connmark --mark 0x400000/0x3fc00000 -g SNAKE_M1",
		"-A SNAKE -m mark ! --mark 0/0xff0000 -m mark --mark 0/0xc0000000 -g SNAKE_SAVE",
		"-A SNAKE -m conntrack ! --ctstate NEW -j RETURN",
		"-A SNAKE_M1 -j MARK --set-xmark 0x10000/0xc0ff0000",
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
	// learning groups routed via a ports-fallback policy still apply
	mustContain(t, m4, "-A SNAKE_P2 -m mac --mac-source aa:bb:cc:00:00:01 -p udp -m set --match-set SNK_2_t4 dst -g SNAKE_M2")
	if strings.Contains(m4, "SNK_3_t4") {
		t.Error("server set for a policy without WebRTC tracking")
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
	mustContain(t, n4, "-A SNAKE_DNS -i br+ -p udp --dport 53 -j REDIRECT --to-ports 53", "-A SNAKE_NAT -o wgc1 -m connmark --mark 0x400000/0x3fc00000 -j MASQUERADE")
	if strings.Contains(n4, "--mac-source") {
		t.Error("global DNS hijack should not need per-MAC rules")
	}
	f4 := plan.Restore["4/filter"]
	mustContain(t, f4,
		"-A SNAKE_FWD -i br+ -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -i br+ -p tcp --dport 443 -m set --match-set SNK_DOH4 dst -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -i br+ -m mac --mac-source aa:bb:cc:00:00:09 -p udp --dport 443 -j REJECT",
		"-A SNAKE_FWD -i br+ -o wgc1 -m connmark --mark 0x400000/0x3fc00000 -j ACCEPT",
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
	mustContain(t, f6, "-A SNAKE_FWD -m connmark --mark 0x800000/0x3fc00000 -j REJECT --reject-with icmp6-adm-prohibited", "icmp6-port-unreachable")
	if strings.Contains(m4, "NFQUEUE --queue-num 4200") {
		t.Error("DNS queue rule without DNSQueue option")
	}
	// 4 shared hooks + 2 per client interface (br+, wgs+, tun2+), per family.
	if len(plan.Hooks) != 20 {
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

func TestBuildDrop(t *testing.T) {
	c, st := states(t)
	st[0].Drops = true // destination-only policy: the whole LAN
	st[1].Drops = true // device policy: its devices
	st[2].Drops = true // IPv6 off: drops still apply on IPv6
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true})
	f4, f6 := plan.Restore["4/filter"], plan.Restore["6/filter"]
	mustContain(t, f4,
		"-A SNAKE_FWD -i br+ -p tcp -m set --match-set SNK_1_x4 dst -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -i br+ -m set --match-set SNK_1_x4 dst -j REJECT --reject-with icmp-port-unreachable",
		"-A SNAKE_FWD -i br+ -p tcp -m set --match-set SNK_1_z4 dst -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -i br+ -m mac --mac-source aa:bb:cc:00:00:01 -m set --match-set SNK_2_x4 dst -j REJECT --reject-with icmp-port-unreachable",
	)
	mustContain(t, f6, "-A SNAKE_FWD -i br+ -m mac --mac-source aa:bb:cc:00:00:09 -m set --match-set SNK_3_z6 dst -j REJECT --reject-with icmp6-port-unreachable")
	if strings.Contains(f4, "-i br+ -m set --match-set SNK_2_x4") {
		t.Error("device policy drop applied LAN-wide")
	}
	if strings.Index(f4, "SNK_1_x4") > strings.Index(f4, "-j ACCEPT") {
		t.Error("drop rejects after accepts")
	}
}

func TestBuildDoTDoHOverrides(t *testing.T) {
	const dotLAN = "-A SNAKE_FWD -i br+ -p tcp --dport 853 -j REJECT"
	const dohLAN = "-A SNAKE_FWD -i br+ -p tcp --dport 443 -m set --match-set SNK_DOH4"
	build := func(dot, doh string) string {
		c, st := states(t)
		for i := range st {
			st[i].Policy.Leak.BlockDoT, st[i].Policy.Leak.BlockDoH = false, false
		}
		c.Settings.BlockDoT, c.Settings.BlockDoH = dot, doh
		return Build(c.Settings, st, Options{}).Restore["4/filter"]
	}
	// policy mode with every toggle off: nothing blocked
	f := build(config.BlockPolicy, config.BlockPolicy)
	if strings.Contains(f, "--dport 853") || strings.Contains(f, "SNK_DOH4") {
		t.Errorf("blocked with every policy toggle off:\n%s", f)
	}
	// always: whole LAN, independently
	f = build(config.BlockAlways, config.BlockPolicy)
	mustContain(t, f, dotLAN)
	if strings.Contains(f, "SNK_DOH4") {
		t.Error("DoH blocked when only DoT is forced")
	}
	f = build(config.BlockPolicy, config.BlockAlways)
	mustContain(t, f, dohLAN)
	if strings.Contains(f, "--dport 853") {
		t.Error("DoT blocked when only DoH is forced")
	}
	// never overrides policies that block
	c, st := states(t)
	c.Settings.BlockDoT, c.Settings.BlockDoH = config.BlockNever, config.BlockPolicy
	f = Build(c.Settings, st, Options{}).Restore["4/filter"]
	if strings.Contains(f, "--dport 853") {
		t.Error("never did not override policy DoT blocking")
	}
	mustContain(t, f, "SNK_DOH4")
}

func TestBuildTunnelConnectionRecovery(t *testing.T) {
	// A connection NATed out a tunnel keeps going into it when its
	// conntrack mark is lost; the rule must come before the WAN-affinity
	// RETURN.
	c, st := states(t)
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true, TunnelAddrs: map[string][]string{
		"wgc1": {"10.66.0.2", "fd00::2"}, "wgc2": {"10.77.0.2"},
	}})
	m4, m6 := plan.Restore["4/mangle"], plan.Restore["6/mangle"]
	rec := "-A SNAKE -m connmark --mark 0/0x3fc00000 -m conntrack --ctstate ESTABLISHED,RELATED --ctrepldst 10.66.0.2 -g SNAKE_M1"
	ret := "-A SNAKE -m conntrack ! --ctstate NEW -j RETURN"
	mustContain(t, m4, rec, "--ctrepldst 10.77.0.2 -g SNAKE_M2", ret)
	if strings.Index(m4, rec) > strings.Index(m4, ret) {
		t.Error("recovery rule after the WAN-affinity RETURN")
	}
	if strings.Contains(m4, "fd00::2") || strings.Contains(m6, "10.66.0.2") {
		t.Error("address of the other family used")
	}
	// IPv6 is routed into wgc1 for policy 1 only (V6Route); policy 2 blocks IPv6.
	mustContain(t, m6, "--ctrepldst fd00::2 -g SNAKE_M1")
	// Policy 3 has no active tunnel: nothing recovers into it.
	if regexp.MustCompile(`ctrepldst \S+ -g SNAKE_M3`).MatchString(m4) {
		t.Error("recovery rule for a policy without tunnel")
	}
}

func TestBuildWANIdentityBeforeMarks(t *testing.T) {
	c, st := states(t)
	plan := Build(c.Settings, st, Options{IPv6: true, WANAddrs: []string{"198.51.100.20", "0.0.0.0", "invalid", "2001:db8::20"}})
	for _, family := range []string{"4", "6"} {
		m := plan.Restore[family+"/mangle"]
		guard := strings.Index(m, "--ctrepldst")
		restore := strings.Index(m, "-A SNAKE -m connmark --mark")
		if guard < 0 || restore < 0 || guard > restore {
			t.Errorf("%s: WAN guard must precede foreign mark restoration", family)
		}
		mustContain(t, m, "-g SNAKE_WAN", "-A SNAKE_WAN -m mark --mark 0/0xc0000000 -j MARK --set-xmark 0/0xff0000", "-A SNAKE_WAN -j RETURN")
		if strings.Contains(m, "--ctrepldst 0.0.0.0") || strings.Contains(m, "invalid") {
			t.Error("invalid WAN address accepted")
		}
	}
	if strings.Contains(plan.Restore["4/mangle"], "2001:db8::20") || strings.Contains(plan.Restore["6/mangle"], "198.51.100.20") {
		t.Error("WAN guard used an address from the other family")
	}
}

func TestSNIRedirect(t *testing.T) {
	c, st := states(t)
	st[1].Policy.Leak.SniffSNI = true // Disney: devices + destinations
	st[2].Policy.Leak.SniffSNI = true // whole device: nothing to sniff
	st[1].Drops = true
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: false, SNIPort: 5340})
	n4 := plan.Restore["4/nat"]
	mustContain(t, n4,
		"-A SNAKE_DNS -i br+ -m mac --mac-source aa:bb:cc:00:00:01 -p tcp --dport 443 -j SNAKE_SNI",
		"-A SNAKE_DNS -i br+ -m mac --mac-source aa:bb:cc:00:00:02 -p tcp --dport 443 -j SNAKE_SNI",
		"-A SNAKE_SNI -m connmark ! --mark 0/0x3fc00000 -j RETURN",
		"-A SNAKE_SNI -d 0.0.0.0/8,10.0.0.0/8",
		"-A SNAKE_SNI -m set --match-set SNK_DOH4 dst -j RETURN",
		"-A SNAKE_SNI -m set --match-set SNK_2_x4 dst -j RETURN",
		"-A SNAKE_SNI -m set --match-set SNK_2_z4 dst -j RETURN",
		"-A SNAKE_SNI -p tcp -j REDIRECT --to-ports 5340",
	)
	if strings.Contains(n4, "aa:bb:cc:00:00:09") {
		t.Error("whole-device policy redirected to the SNI proxy")
	}
	if strings.Index(n4, "-j REDIRECT --to-ports 5340") < strings.Index(n4, "SNK_2_z4") {
		t.Error("redirect before the RETURN rules")
	}
	mustContain(t, plan.Restore["4/filter"],
		"-A SNAKE_FWD -i br+ -m mac --mac-source aa:bb:cc:00:00:01 -p udp --dport 443 -m connmark --mark 0/0x3fc00000 -j REJECT --reject-with icmp-port-unreachable")
	// No IPv6 NAT: IPv6 cannot be redirected, and its QUIC is left alone.
	if strings.Contains(plan.Restore["6/filter"], "--dport 443 -m connmark") {
		t.Error("IPv6 QUIC rejected without an IPv6 redirect")
	}
	// Proxy not running: no redirect, no QUIC rejection.
	plan = Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true, SNIPort: 0})
	for k, v := range plan.Restore {
		if strings.Contains(v, "SNAKE_SNI") || strings.Contains(v, "--dport 443 -m connmark") {
			t.Errorf("%s has SNI rules without the proxy:\n%s", k, v)
		}
	}
	// With IPv6 NAT both families are redirected.
	plan = Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true, SNIPort: 5340})
	mustContain(t, plan.Restore["6/nat"], "-A SNAKE_SNI -m set --match-set SNK_DOH6 dst -j RETURN", "-A SNAKE_SNI -p tcp -j REDIRECT --to-ports 5340")
}

func TestVPNServerClients(t *testing.T) {
	c, st := states(t)
	if got := c.Settings.ClientInterfaces(); strings.Join(got, " ") != "br+ wgs+ tun2+" {
		t.Fatalf("client interfaces %v", got)
	}
	// Disney: a LAN group plus a WireGuard peer and an OpenVPN subnet.
	st[1].Clients = append(st[1].Clients, "10.6.0.2", "10.8.0.0/24", "fd00:6::2")
	st[1].Policy.Leak.SniffSNI = true
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true, LANAddr: "192.168.50.1", SNIPort: 5340})
	m4, n4, f4 := plan.Restore["4/mangle"], plan.Restore["4/nat"], plan.Restore["4/filter"]
	mustContain(t, m4,
		"-A SNAKE_P2 -s 10.6.0.2 -m set --match-set SNK_2_d4 dst -g SNAKE_M2",
		"-A SNAKE_P2 -s 10.8.0.0/24 -m set --match-set SNK_2_d4 dst -g SNAKE_M2",
		"-A SNAKE_P2 -m mac --mac-source aa:bb:cc:00:00:01 -m set --match-set SNK_2_d4 dst -g SNAKE_M2",
	)
	if strings.Contains(m4, "fd00:6::2") {
		t.Error("IPv6 device in IPv4 rules")
	}
	mustContain(t, plan.Restore["6/mangle"], "-A SNAKE_P2 -s fd00:6::2 -m set --match-set SNK_2_d6 dst -g SNAKE_M2")
	if strings.Contains(plan.Restore["6/mangle"], "10.6.0.2") {
		t.Error("IPv4 device in IPv6 rules")
	}
	// Destination policy (Netflix): every client interface is covered.
	for _, lan := range []string{"br+", "wgs+", "tun2+"} {
		mustContain(t, f4,
			"-A SNAKE_FWD -i "+lan+" -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
			"-A SNAKE_FWD -i "+lan+" -o wgc1 -m connmark --mark 0x400000/0x3fc00000 -j ACCEPT",
			"-A SNAKE_FWD -i wgc1 -o "+lan+" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		)
		var found bool
		for _, h := range plan.Hooks {
			if !h.V6 && h.Table == "mangle" && h.Chain == "PREROUTING" && strings.Join(h.Args, " ") == "-i "+lan+" -j SNAKE" {
				found = true
			}
		}
		if !found {
			t.Errorf("no mangle hook for %s", lan)
		}
	}
	// DNS hijack: REDIRECT on bridges, DNAT to the LAN address on VPN servers.
	mustContain(t, n4,
		"-A SNAKE_DNS -i br+ -p udp --dport 53 -j REDIRECT --to-ports 53",
		"-A SNAKE_DNS -i wgs+ -p udp --dport 53 -j DNAT --to-destination 192.168.50.1:53",
		"-A SNAKE_DNS -i tun2+ -p tcp --dport 53 -j DNAT --to-destination 192.168.50.1:53",
	)
	if strings.Contains(plan.Restore["6/nat"], "-i wgs+ -p udp --dport 53") {
		t.Error("IPv6 DNS hijack on a VPN server interface")
	}
	// Device scoping on a routed interface uses addresses, never MACs.
	mustContain(t, n4,
		"-A SNAKE_DNS -i wgs+ -s 10.6.0.2 -p tcp --dport 443 -j SNAKE_SNI",
		"-A SNAKE_DNS -i br+ -m mac --mac-source aa:bb:cc:00:00:01 -p tcp --dport 443 -j SNAKE_SNI",
	)
	if strings.Contains(n4, "-i wgs+ -m mac") || strings.Contains(n4, "-i tun2+ -m mac") {
		t.Error("MAC match on a routed interface")
	}
	// The DNS inspector sees answers sent to VPN clients.
	plan = Build(c.Settings, st, Options{DNSQueue: 4200})
	mustContain(t, plan.Restore["4/mangle"], "-A SNAKE_DNSO -o wgs+ -j NFQUEUE --queue-num 4200", "-A SNAKE_DNSO -o tun2+ -j NFQUEUE")
	// Without a LAN address, VPN clients' DNS is not hijacked.
	plan = Build(c.Settings, st, Options{})
	if strings.Contains(plan.Restore["4/nat"], "DNAT") {
		t.Error("DNAT without a LAN address")
	}
}

func TestDeviceOnlyInOtherFamily(t *testing.T) {
	c, st := states(t)
	// A whole-device policy for an IPv4 VPN peer must not become a
	// whole-LAN policy in the IPv6 table.
	st[2].Clients = []string{"10.6.0.9"}
	st[2].IPv6Mode = V6Block
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true})
	mustContain(t, plan.Restore["4/mangle"], "-A SNAKE_P3 -s 10.6.0.9 -g SNAKE_M3")
	if regexp.MustCompile(`(?m)^-A SNAKE_P3 -g SNAKE_M3`).MatchString(plan.Restore["6/mangle"]) {
		t.Error("IPv4-only device policy matches every IPv6 client")
	}
	if strings.Contains(plan.Restore["6/filter"], "-p udp --dport 443 -j REJECT") {
		t.Error("QUIC block for an IPv4-only device leaked to every IPv6 client")
	}
}

// Excluded devices return from the policy's chains before anything
// matches: routing, WebRTC session refresh, drop: rules and its leak
// protection. Other policies' merged leak protection is untouched.
func TestExcludedDevices(t *testing.T) {
	c, st := states(t)
	st[0].Excluded = []string{"aa:bb:cc:00:00:99", "192.168.50.77", "fd00::77"}
	st[0].Drops = true
	st[0].Policy.Leak.SniffSNI = true
	plan := Build(c.Settings, st, Options{IPv6: true, IPv6NAT: true, SNIPort: 5340})
	m4, n4, f4, m6 := plan.Restore["4/mangle"], plan.Restore["4/nat"], plan.Restore["4/filter"], plan.Restore["6/mangle"]

	// Policy chain: excluded first, then the session refresh, then the
	// claimed-already check and the matches.
	p1 := regexp.MustCompile(`(?m)^-A SNAKE_P1 .*$`).FindAllString(m4, -1)
	if len(p1) < 4 || p1[0] != "-A SNAKE_P1 -m mac --mac-source aa:bb:cc:00:00:99 -j RETURN" || p1[1] != "-A SNAKE_P1 -s 192.168.50.77 -j RETURN" {
		t.Fatalf("policy chain does not start with the exclusions:\n%s", strings.Join(p1, "\n"))
	}
	mustContain(t, m4, "-A SNAKE_P1 -m conntrack --ctstate NEW -m set --match-set SNK_1_d4 dst -j SET --add-set SNK_1_s4 src --exist")
	if strings.Contains(m4, "-A SNAKE -m conntrack --ctstate NEW -m set --match-set SNK_1_d4 dst -j SET") {
		t.Error("session refresh still before the exclusions")
	}
	if strings.Contains(m4, "fd00::77") || !strings.Contains(m6, "-A SNAKE_P1 -s fd00::77 -j RETURN") {
		t.Error("exclusions in the wrong family")
	}
	// drop: rules and leak protection in guarded chains.
	mustContain(t, f4,
		"-A SNAKE_FWD -j SNAKE_X1_DROP",
		"-A SNAKE_X1_DROP -m mac --mac-source aa:bb:cc:00:00:99 -j RETURN",
		"-A SNAKE_X1_DROP -i br+ -p tcp -m set --match-set SNK_1_x4 dst -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -j SNAKE_X1_DOT",
		"-A SNAKE_X1_DOT -s 192.168.50.77 -j RETURN",
		"-A SNAKE_X1_DOT -i br+ -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A SNAKE_FWD -j SNAKE_X1_SNIQ",
	)
	mustContain(t, n4,
		"-A SNAKE_DNS -j SNAKE_X1_DNS",
		"-A SNAKE_X1_DNS -m mac --mac-source aa:bb:cc:00:00:99 -j RETURN",
		"-A SNAKE_X1_DNS -i br+ -p udp --dport 53 -j REDIRECT --to-ports 53",
		"-A SNAKE_DNS -j SNAKE_X1_SNI",
		"-A SNAKE_X1_SNI -i br+ -p tcp --dport 443 -j SNAKE_SNI",
	)
	// The policy no longer joins the merged LAN-wide scope.
	if strings.Contains(f4, "-A SNAKE_FWD -i br+ -p tcp --dport 853") {
		t.Error("excluded policy still in the merged DoT scope")
	}
	// Router-wide "always block" covers excluded devices too.
	c.Settings.BlockDoT = config.BlockAlways
	f4 = Build(c.Settings, st, Options{}).Restore["4/filter"]
	if strings.Contains(f4, "SNAKE_X1_DOT") || !strings.Contains(f4, "-A SNAKE_FWD -i br+ -p tcp --dport 853") {
		t.Errorf("block_dot=always not router-wide:\n%s", f4)
	}
	// Removing the exclusions deletes the guard chains.
	st[0].Excluded = nil
	plan = Build(c.Settings, st, Options{Existing: map[string][]string{"4/filter": {"SNAKE_FWD", "SNAKE_X1_DROP"}}})
	mustContain(t, plan.Restore["4/filter"], "-X SNAKE_X1_DROP")
}
