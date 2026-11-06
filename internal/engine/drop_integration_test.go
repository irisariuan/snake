//go:build integration

package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsinspect"
)

// TestIntegrationDrop checks drop: rules end to end: DNS answers for dropped
// names land in the drop set (not the route set), and a LAN client's TCP
// connections to dropped addresses are refused by the router.
func TestIntegrationDrop(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	// The integration tests share one network namespace: leave it as found.
	t.Cleanup(func() {
		_ = exec.Command("sh", "-c", "ip link del lanv; ip link del br0; ip link del wan0; ip link del wgc1; "+
			"for s in $(ipset list -n | grep ^SNK_); do ipset flush $s; done").Run()
	})
	sh(t, "ip link set lo up")
	sh(t, "ip link show br0 >/dev/null 2>&1 || ip link add br0 type bridge; ip link set br0 up")
	sh(t, "ip link show wgc1 >/dev/null 2>&1 || ip tuntap add mode tun dev wgc1; ip link set wgc1 up")
	// "WAN": a tun device that swallows everything routed to it.
	sh(t, "ip link show wan0 >/dev/null 2>&1 || ip tuntap add mode tun dev wan0; ip link set wan0 up; ip route replace 203.0.113.0/24 dev wan0")
	stop := fakeDNS(t, map[string][]string{
		"www.example.com":    {"203.0.113.10"},
		"ads.example.com":    {"203.0.113.20"},                      // drop beats the include
		"ok.ads.example.com": {"203.0.113.21"},                      // ! exempts it
		"cdn.partner.test":   {"x.tracker.example", "203.0.113.30"}, // drop via CNAME
		"unrelated.test":     {"203.0.113.40"},
	})
	defer stop()

	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: false,
		Domains: []string{"example.com", "drop:ads.example.com", "drop:**.tracker.example", "!=ok.ads.example.com", "drop:cidr:203.0.113.50"},
		Leak:    config.Leak{IPv6: "off", WebRTC: "off"}}}
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
	if err := e.Apply("drop test"); err != nil {
		t.Fatal(err)
	}
	defer e.dns.Stop()
	for _, q := range []string{"www.example.com", "ads.example.com", "ok.ads.example.com", "cdn.partner.test", "unrelated.test"} {
		if _, err := dnsinspect.Query("127.0.0.1:53", q, 3*time.Second); err != nil {
			t.Fatalf("query %s: %v", q, err)
		}
	}
	drop, route := sh(t, "ipset list SNK_1_x4"), sh(t, "ipset list SNK_1_d4")
	for _, ip := range []string{"203.0.113.20", "203.0.113.30"} {
		if !strings.Contains(drop, ip) || strings.Contains(route, ip) {
			t.Errorf("%s should be in the drop set only\ndrop:\n%s\nroute:\n%s", ip, drop, route)
		}
	}
	for _, ip := range []string{"203.0.113.10", "203.0.113.21", "203.0.113.40"} {
		if strings.Contains(drop, ip) {
			t.Errorf("%s must not be dropped", ip)
		}
	}
	if !strings.Contains(route, "203.0.113.10") || !strings.Contains(sh(t, "ipset list SNK_1_z4"), "203.0.113.50") {
		t.Error("route set / drop:cidr: set not filled")
	}
	if st := e.dns.Stats(); st.Dropped != 2 {
		t.Errorf("dropped = %d, want 2", st.Dropped)
	}
	dt := e.TestDomain("ads.example.com")
	if !dt.Blocked || dt.Matched != "drop:ads.example.com" || len(dt.Addrs) != 1 || dt.Addrs[0].Blocked != "SNK_1_x4" {
		t.Errorf("TestDomain = %+v", dt)
	}
	v, err := e.LearnedAddrs("p", LearnedDrop, "", 0)
	if err != nil || v.Total != 2 || v.Unknown != 0 {
		t.Errorf("LearnedAddrs(drop) = %+v %v", v, err)
	}

	// A LAN client in its own namespace, forwarded through this one.
	if exec.Command("ip", "netns", "add", "snakelan").Run() != nil {
		t.Skip("cannot create a network namespace for the forwarding check")
	}
	defer exec.Command("ip", "netns", "del", "snakelan").Run()
	sh(t, "sysctl -qw net.ipv4.ip_forward=1")
	sh(t, "ip link add lanv type veth peer name lanc && ip link set lanc netns snakelan && ip link set lanv master br0 && ip link set lanv up")
	sh(t, "ip addr add 192.168.77.1/24 dev br0")
	sh(t, "ip netns exec snakelan sh -c 'ip link set lo up; ip addr add 192.168.77.2/24 dev lanc; ip link set lanc up; ip route add default via 192.168.77.1'")
	connect := func(ip string) string {
		out, _ := exec.Command("ip", "netns", "exec", "snakelan", "timeout", "2", "bash", "-c", "exec 3<>/dev/tcp/"+ip+"/80 && echo open").CombinedOutput()
		return string(out)
	}
	time.Sleep(200 * time.Millisecond)
	for _, ip := range []string{"203.0.113.20", "203.0.113.30", "203.0.113.50"} {
		start := time.Now()
		out := connect(ip)
		if !strings.Contains(out, "refused") || time.Since(start) > time.Second {
			t.Errorf("connect %s: want a fast refusal, got %q after %v", ip, out, time.Since(start))
		}
	}
	// Not dropped: no reset from the router (the SYN goes out and nothing answers).
	if out := connect("203.0.113.40"); strings.Contains(out, "refused") {
		t.Errorf("connect 203.0.113.40 was refused: %q", out)
	}
}
