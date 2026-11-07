//go:build integration

// Integration test: applies real iptables/ipset/ip state inside a throwaway
// network namespace. Run as root:
//
//	unshare -n go test -tags integration ./internal/engine -run Integration -v
package engine

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsinspect"
	"github.com/irisariuan/snake/internal/health"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/webrtc"
)

// fakeMerlin intercepts router-only tools and runs everything else for real.
type fakeMerlin struct{ real system.Exec }

func (f fakeMerlin) Run(name string, args ...string) (string, error) {
	return f.RunInput("", name, args...)
}

func (f fakeMerlin) RunInput(in, name string, args ...string) (string, error) {
	switch name {
	case "nvram":
		if len(args) == 2 && args[1] == "wan0_ipaddr" {
			return "198.18.0.1", nil
		}
		if len(args) == 2 && args[1] == "ipv6_service" {
			return "native", nil
		}
		if len(args) == 2 && strings.HasSuffix(args[1], "_state") {
			return "2", nil
		}
		return "", nil
	case "conntrack":
		if len(args) > 0 && args[0] == "-L" {
			break // listing the connection table: real
		}
		return "", nil
	case "service", "modprobe":
		return "", nil
	case "wg":
		return "peerkey\t" + strconv.FormatInt(time.Now().Unix(), 10), nil
	}
	return f.real.RunInput(in, name, args...)
}

func sh(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", cmd, err, out)
	}
	return string(out)
}

func TestIntegrationApply(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	sh(t, "ip link add br0 type bridge && ip link set br0 up")
	for _, i := range []string{"wgc1", "wgc2", "wgc3", "tun12"} {
		sh(t, "ip tuntap add mode tun dev "+i+" && ip link set "+i+" up")
	}
	_, err := os.Stat("/proc/net/if_inet6")
	v6 := err == nil
	sh(t, "ip addr add 10.2.0.2/32 dev wgc1")
	if v6 {
		sh(t, "ip -6 addr add 2001:db8::2/128 dev wgc1")
	} else {
		t.Log("kernel without IPv6: skipping IPv6 checks")
	}

	dir := t.TempDir()
	b, _ := os.ReadFile("../../testdata/config.json")
	var c config.Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	c.ApplyDefaults()
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), &c); err != nil {
		t.Fatal(err)
	}
	p := DefaultPaths(dir)
	e := New(p, fakeMerlin{})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	e.DetectCaps()
	e.SeedHealth()
	e.decide()
	if err := e.Apply("integration"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := e.Apply("integration (idempotent)"); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	save := sh(t, "iptables-save")
	for _, s := range []string{"-A PREROUTING -i br+ -j SNAKE", "-A SNAKE_P1 -m set --match-set SNK_1_d4 dst -g SNAKE_M1", ":SNAKE_P3", "-A FORWARD -j SNAKE_FWD"} {
		if !strings.Contains(save, s) {
			t.Errorf("iptables-save missing %q", s)
		}
	}
	if n := strings.Count(save, "-A PREROUTING -i br+ -j SNAKE\n"); n != 1 {
		t.Errorf("hook installed %d times", n)
	}
	rules := sh(t, "ip -4 rule show")
	for _, s := range []string{"5201:", "5202:", "5203:", "5001:", "4981:"} {
		if !strings.Contains(rules, s) {
			t.Errorf("ip rule missing %s:\n%s", s, rules)
		}
	}
	if n := strings.Count(rules, "5201:"); n != 1 {
		t.Errorf("rule 5201 present %d times", n)
	}
	if r := sh(t, "ip -4 route show table 1001"); !strings.Contains(r, "default dev wgc1") {
		t.Errorf("table 1001: %s", r)
	}
	if r := sh(t, "ip -6 route show table 1001 || true"); v6 && !strings.Contains(r, "default dev wgc1") {
		t.Errorf("v6 table 1001 (tunnel has IPv6): %s", r)
	}
	sets := sh(t, "ipset list -n")
	for _, s := range []string{"SNK_1_d4", "SNK_1_n4", "SNK_1_s4", "SNK_1_t4", "SNK_2_d4", "SNK_DOH4"} {
		if !strings.Contains(sets, s) {
			t.Errorf("missing set %s", s)
		}
	}
	// WebRTC peers are device sessions (session chain), not a peer set.
	if strings.Contains(sets, "SNK_1_r4") {
		t.Error("former WebRTC peer set SNK_1_r4 still created")
	}
	// With NFQUEUE, WebRTC learns peers as sessions (session chain);
	// without it, the port fallback learns none.
	if save := sh(t, "iptables-save -t mangle"); e.Caps().NFQueue != strings.Contains(save, "-A SNAKE_P1 -j SNAKE_Q1") {
		t.Errorf("session chain present = %v with NFQUEUE = %v", !e.Caps().NFQueue, e.Caps().NFQueue)
	}
	if !strings.Contains(sh(t, "ipset list SNK_1_n4"), "23.246.0.0/18") {
		t.Error("CIDR not loaded")
	}

	// Failover: wgc1 dies -> policy 1 moves to ovpnc2 (tun12).
	e.mon.Set(health.Status{Tunnel: "wgc1", Iface: "wgc1", Exists: true, Up: true, Reason: "probe failed 3 times"})
	e.mon.Set(health.Status{Tunnel: "ovpnc2", Iface: "tun12", Exists: true, Up: true, LinkOK: true, ProbeOK: true, Healthy: true, HealthySince: time.Now()})
	if ch := e.decide(); len(ch) != 1 || ch[0] != 1 {
		t.Fatalf("decide changed = %v", ch)
	}
	if err := e.Apply("failover"); err != nil {
		t.Fatal(err)
	}
	if r := sh(t, "ip -4 route show table 1001"); !strings.Contains(r, "default dev tun12") {
		t.Errorf("after failover table 1001: %s", r)
	}
	if v6 {
		if r := sh(t, "ip -6 route show table 1001"); !strings.Contains(r, "unreachable default") {
			t.Errorf("v6 after failover to v4-only tunnel should be unreachable: %s", r)
		}
		if !strings.Contains(sh(t, "ip6tables-save -t filter"), "-A SNAKE_FWD -m connmark --mark 0x400000/0x3fc00000 -j REJECT") {
			t.Error("v6 block rule not installed after failover to v4-only tunnel")
		}
	}

	// Everything down -> kill switch (policy 1) vs fall-through (policy 2).
	for k := range e.mon.Snapshot() {
		e.mon.Set(health.Status{Tunnel: k, Reason: "interface down"})
	}
	e.decide()
	if err := e.Apply("all down"); err != nil {
		t.Fatal(err)
	}
	if r := sh(t, "ip -4 route show table 1001"); !strings.Contains(r, "unreachable default") {
		t.Errorf("kill switch: %s", r)
	}
	if r := sh(t, "ip -4 route show table 1002"); strings.TrimSpace(r) != "" {
		t.Errorf("no-kill policy should fall through to main: %q", r)
	}

	// Remove a policy -> its chains, rules and sets disappear.
	c2 := e.Config()
	c2.Policies = c2.Policies[:1]
	if err := e.SetConfig(c2); err != nil {
		t.Fatal(err)
	}
	save = sh(t, "iptables-save")
	if strings.Contains(save, "SNAKE_P2") || strings.Contains(save, "SNAKE_P3") {
		t.Error("stale chains left behind")
	}
	if strings.Contains(sh(t, "ip -4 rule show"), "5202:") {
		t.Error("stale rule left behind")
	}
	if strings.Contains(sh(t, "ipset list -n"), "SNK_2_") {
		t.Error("stale sets left behind")
	}
	if e.caps.NFQueue {
		if err := e.rtc.Configure([]webrtc.PolicyTrack{{ID: 1, Queue: 4201, Mark: 0x10000}}, true); err != nil {
			t.Errorf("nfqueue listener: %v", err)
		}
		// Real STUN through the queue: a plain binding request is learned as
		// a server, an ICE connectivity check as a peer.
		sh(t, "ip tuntap add mode tun dev stunout && ip link set stunout up && ip addr add 192.0.2.1/24 dev stunout && ip route add 203.0.113.0/24 dev stunout && ip route add 198.51.100.0/24 dev stunout")
		sh(t, "iptables -t mangle -I OUTPUT -p udp --dport 3478 -m mark --mark 0/0xff0000 -j NFQUEUE --queue-num 4201 --queue-bypass")
		sendSTUN(t, "203.0.113.7:3478", stunPacket(0x0001))
		sendSTUN(t, "198.51.100.5:3478", stunPacket(0x0001, 0x0006, 0x0024, 0x802A))
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && e.rtc.Stats()[1].Servers+e.rtc.Stats()[1].Learned < 2 {
			time.Sleep(50 * time.Millisecond)
		}
		if srv := sh(t, "ipset list SNK_1_t4"); !strings.Contains(srv, "203.0.113.7") || strings.Contains(srv, "198.51.100.5") {
			t.Errorf("server set:\n%s", srv)
		}
		var peers []string
		for _, se := range e.Sessions(1) {
			if se.Source == SessionWebRTC {
				peers = append(peers, se.Addr)
			}
		}
		if p := strings.Join(peers, ","); p != "198.51.100.5" {
			t.Errorf("WebRTC peer sessions: %q", p)
		}
		t.Logf("webrtc stats: %+v", e.rtc.Stats()[1])
		sh(t, "iptables -t mangle -D OUTPUT -p udp --dport 3478 -m mark --mark 0/0xff0000 -j NFQUEUE --queue-num 4201 --queue-bypass")
		e.rtc.Stop()
	}
	t.Logf("plan:\n%s", e.Plan().Restore["4/mangle"])
}

func stunPacket(typ uint16, attrs ...uint16) []byte {
	b := make([]byte, 20, 20+8*len(attrs))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(8*len(attrs)))
	binary.BigEndian.PutUint32(b[4:8], 0x2112A442)
	for _, a := range attrs {
		b = binary.BigEndian.AppendUint16(b, a)
		b = binary.BigEndian.AppendUint16(b, 4)
		b = append(b, 0, 0, 0, 0)
	}
	return b
}

func sendSTUN(t *testing.T, addr string, msg []byte) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
}

// fakeDNS answers A queries on 127.0.0.1:53 from a fixed table.
func fakeDNS(t *testing.T, table map[string][]string) func() {
	return fakeDNSFunc(t, func(name string) []string { return table[name] })
}

// fakeDNSFunc answers A queries on 127.0.0.1:53 with lookup(name): IPs or
// CNAME targets, in order.
func fakeDNSFunc(t *testing.T, lookup func(name string) []string) func() {
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) == 0 {
				continue
			}
			q := m.Questions[0]
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: m.Header.ID, Response: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			owner := q.Name
			if q.Type == dnsmessage.TypeA {
				for _, v := range lookup(strings.TrimSuffix(q.Name.String(), ".")) {
					if ip := net.ParseIP(v); ip != nil {
						var a [4]byte
						copy(a[:], ip.To4())
						_ = b.AResource(dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: a})
					} else {
						cn := dnsmessage.MustNewName(v + ".")
						_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.CNAMEResource{CNAME: cn})
						owner = cn
					}
				}
			}
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return func() { pc.Close() }
}

func TestIntegrationDNSInspector(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	sh(t, "ip link set lo up")
	sh(t, "ip link show br0 >/dev/null 2>&1 || ip link add br0 type bridge; ip link set br0 up")
	sh(t, "ip link show wgc1 >/dev/null 2>&1 || ip tuntap add mode tun dev wgc1; ip link set wgc1 up")
	stop := fakeDNS(t, map[string][]string{
		"ipv4-c042-lhr001.oca.nflxvideo.net": {"203.0.113.50"},                         // regex rule
		"play.partner.tv":                    {"x1.cdn.nflxvideo.net", "203.0.113.51"}, // via CNAME -> **.nflxvideo.net
		"customerevents.netflix.com":         {"203.0.113.52"},                         // excluded
		"api.nflxso.net":                     {"203.0.113.53"},                         // keyword ~nflxso
		"www.example.org":                    {"203.0.113.54"},                         // no match
	})
	defer stop()

	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "nf", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true,
		Domains: []string{"netflix.com", "**.nflxvideo.net", `/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/`, "!=customerevents.netflix.com"},
		Lists:   []string{"extra"}, // "~nflxso" comes from a rule list
		Leak:    config.Leak{IPv6: "off", WebRTC: "off"}}}
	c.RuleLists = []config.RuleList{{Name: "extra", Domains: []string{"~nflxso"}}}
	c.Settings.PreResolve = false
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	e := New(DefaultPaths(dir), fakeMerlin{})
	e.daemon = true
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	e.DetectCaps()
	if !e.caps.NFQueue {
		t.Skip("kernel without NFQUEUE")
	}
	e.SeedHealth()
	e.decide()
	if err := e.Apply("dns test"); err != nil {
		t.Fatal(err)
	}
	defer e.dns.Stop()
	if !e.dns.Running() {
		t.Fatal("inspector not running")
	}
	for _, q := range []string{"ipv4-c042-lhr001.oca.nflxvideo.net", "play.partner.tv", "customerevents.netflix.com", "api.nflxso.net", "www.example.org"} {
		a, err := dnsinspect.Query("127.0.0.1:53", q, 3*time.Second)
		if err != nil {
			t.Fatalf("query %s: %v", q, err)
		}
		t.Logf("%s -> chain %v ips %v", q, a.Chain, a.IPs)
	}
	set := sh(t, "ipset list SNK_1_d4")
	for _, ip := range []string{"203.0.113.50", "203.0.113.51", "203.0.113.53"} {
		if !strings.Contains(set, ip) {
			t.Errorf("%s should have been added:\n%s", ip, set)
		}
	}
	for _, ip := range []string{"203.0.113.52", "203.0.113.54"} {
		if strings.Contains(set, ip) {
			t.Errorf("%s must not be added", ip)
		}
	}
	st := e.dns.Stats()
	t.Logf("inspector stats: %+v", st)
	if st.Matched != 3 {
		t.Errorf("matched = %d, want 3", st.Matched)
	}
	// Policy addresses view: kernel set joined with the inspector's records.
	lv, err := e.LearnedAddrs("nf", LearnedDNS, "partner", 0)
	if err != nil || lv.Total != 3 || len(lv.Addrs) != 1 || lv.Addrs[0].Matched != "x1.cdn.nflxvideo.net" || lv.Addrs[0].Rule != "**.nflxvideo.net" || lv.Addrs[0].Source != "policy" {
		t.Errorf("LearnedAddrs = %+v %v", lv, err)
	}
	if n, err := e.ForgetLearned("nf", ForgetRequest{Kind: LearnedDNS, Addrs: []string{"203.0.113.51"}}); err != nil || n != 1 || strings.Contains(sh(t, "ipset list SNK_1_d4"), "203.0.113.51") {
		t.Errorf("forget: %d %v", n, err)
	}
	// The domain tester sees the CNAME chain and the matching rule.
	dt := e.TestDomain("play.partner.tv")
	if dt.Policy != "nf" || dt.Matched != "**.nflxvideo.net" || dt.Via != "x1.cdn.nflxvideo.net" || len(dt.Addrs) != 1 || dt.Addrs[0].InSet != "SNK_1_d4" {
		t.Errorf("TestDomain = %+v", dt)
	}
}
