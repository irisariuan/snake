//go:build integration

package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
)

// TestIntegrationLostConnmark: a connection routed through a tunnel keeps
// using it while another component rewrites its conntrack mark. On a router
// running v1.0.4 such connections timed out (deleting the WAN-affinity
// RETURN rule fixed them). This kernel keeps forwarding them through the
// tunnel even without the fix, so the test checks that the rule which
// recognises tunnel connections by their NAT address carries the packets.
func TestIntegrationLostConnmark(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 needed for the test client/server")
	}
	if _, err := exec.LookPath("conntrack"); err != nil {
		t.Skip("conntrack tool needed")
	}
	t.Cleanup(func() {
		_ = exec.Command("sh", "-c", "ip netns del snakelan; ip netns del snakesrv; ip link del wanv; ip link del wgc1; ip link del br0; "+
			"iptables -t nat -D POSTROUTING -o wanv -j MASQUERADE; for s in $(ipset list -n | grep ^SNK_); do ipset flush $s; done").Run()
	})
	if exec.Command("ip", "netns", "add", "snakelan").Run() != nil || exec.Command("ip", "netns", "add", "snakesrv").Run() != nil {
		t.Skip("cannot create network namespaces")
	}
	// Earlier tests leave interfaces with these names behind (e.g. wgc1 as a tun).
	_ = exec.Command("sh", "-c", "ip link del br0; ip link del wgc1; ip link del wanv; ip route del 203.0.113.80").Run()
	sh(t, "ip link set lo up; sysctl -qw net.ipv4.ip_forward=1")
	// The LAN side is a plain veth named br0: a real bridge would send
	// packets through iptables twice here (bridge netfilter).
	sh(t, "ip link del br0 2>/dev/null; ip link add br0 type veth peer name lanc; ip link set lanc netns snakelan; ip addr add 192.168.77.1/24 dev br0; ip link set br0 up")
	sh(t, "ip netns exec snakelan sh -c 'ip link set lo up; ip addr add 192.168.77.2/24 dev lanc; ip link set lanc up; ip route add default via 192.168.77.1'")
	// The server is reachable over WAN and over a working "tunnel" (a veth).
	// It drops packets whose source does not match the interface they came
	// in on (rp_filter), like an ISP drops the tunnel's address on WAN.
	sh(t, "ip link add wanv type veth peer name wans; ip link set wans netns snakesrv; ip addr add 198.18.0.1/30 dev wanv; ip link set wanv up")
	sh(t, "ip link add wgc1 type veth peer name tuns; ip link set tuns netns snakesrv; ip addr add 10.66.0.2/30 dev wgc1; ip link set wgc1 up")
	sh(t, "ip netns exec snakesrv sh -c 'sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1; ip link set lo up; "+
		"ip addr add 198.18.0.2/30 dev wans; ip addr add 10.66.0.1/30 dev tuns; ip addr add 203.0.113.80/32 dev lo; "+
		"sysctl -qw net.ipv4.conf.wans.rp_filter=1 net.ipv4.conf.tuns.rp_filter=1; ip link set wans up; ip link set tuns up; ip route add default via 198.18.0.1'")
	sh(t, "ip route add 203.0.113.80 via 198.18.0.2; iptables -t nat -A POSTROUTING -o wanv -j MASQUERADE")
	srv := exec.Command("ip", "netns", "exec", "snakesrv", "python3", "-c", `
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("203.0.113.80", 80)); s.listen()
def serve(c):
    f = c.makefile("rwb")
    for line in f:
        f.write(line); f.flush()
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
`)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()

	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true, Domains: []string{"example.com"},
		Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
	c.Settings.PreResolve = false
	c.Settings.LANInterfaces = "br0"
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	e := New(DefaultPaths(dir), fakeMerlin{})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	e.DetectCaps()
	e.SeedHealth()
	e.decide()
	if err := e.Apply("lost connmark test"); err != nil {
		t.Fatal(err)
	}
	sh(t, "ipset add SNK_1_d4 203.0.113.80") // the policy routes the server
	// Another firmware component that keeps rewriting conntrack marks with
	// its own value (none of snake's bits), after snake has seen the packet.
	foreign := "-t mangle -A POSTROUTING -d 203.0.113.80 -j CONNMARK --set-xmark 0x1/0xffffffff"
	sh(t, "iptables "+foreign)
	defer exec.Command("sh", "-c", "iptables "+strings.Replace(foreign, "-A", "-D", 1)).Run()

	time.Sleep(300 * time.Millisecond)
	runClient := func(label string) {
		cli := exec.Command("ip", "netns", "exec", "snakelan", "python3", "-c", `
import socket
try:
    c = socket.create_connection(("203.0.113.80", 80), timeout=3); f = c.makefile("rwb")
    for w in (b"one", b"two", b"three"):
        f.write(w + b"\n"); f.flush(); print(f.readline().decode().strip(), flush=True)
except Exception as e:
    print("stalled " + type(e).__name__, flush=True)
`)
		out, err := cli.CombinedOutput()
		if got := strings.Fields(string(out)); err != nil || strings.Join(got, " ") != "one two three" {
			t.Fatalf("%s: connection failed: %q (%v)", label, out, err)
		}
	}
	runClient("tunnel with overwritten connmark")
	// The packets after the first were carried by the rule that recognises
	// tunnel connections by their NAT address.
	rec := sh(t, "iptables -t mangle -L SNAKE -v -n -x | grep ctrepldst || true")
	if f := strings.Fields(rec); len(f) == 0 || f[0] == "0" {
		t.Errorf("tunnel recovery rule missing or unused:\n%s", rec)
	}

	// Simulate Adaptive QoS on both NEW and ESTABLISHED packets. Its
	// category deliberately equals policy 1 in the old shared mark bits.
	// Separate policy ownership must survive classification, QoS bits
	// must survive policy assignment, and the egress packet must have its
	// QoS classification restored after the routing decision.
	sh(t, "iptables "+strings.Replace(foreign, "-A", "-D", 1))
	sh(t, "iptables -t mangle -N TEST_CLASSIFY; iptables -t mangle -A TEST_CLASSIFY -j CONNMARK --set-xmark 0x80010002/0xc03fffff; iptables -t mangle -A TEST_CLASSIFY -j MARK --set-xmark 0x80010002/0xc03fffff; iptables -t mangle -I PREROUTING 1 -i br0 -d 203.0.113.80 -j TEST_CLASSIFY")
	defer exec.Command("sh", "-c", "iptables -t mangle -D PREROUTING -i br0 -d 203.0.113.80 -j TEST_CLASSIFY; iptables -t mangle -F TEST_CLASSIFY; iptables -t mangle -X TEST_CLASSIFY").Run()
	sh(t, "iptables -t mangle -N TEST_QOS; iptables -t mangle -A TEST_QOS -j RETURN; iptables -t mangle -A POSTROUTING -o wgc1 -m mark --mark 0x80010002/0xc03fffff -j TEST_QOS")
	defer exec.Command("sh", "-c", "iptables -t mangle -D POSTROUTING -o wgc1 -m mark --mark 0x80010002/0xc03fffff -j TEST_QOS; iptables -t mangle -F TEST_QOS; iptables -t mangle -X TEST_QOS").Run()
	runClient("tunnel with QoS enabled")
	ct := sh(t, "conntrack -L -p tcp -s 192.168.77.2 -d 203.0.113.80 --mark 0x80410002/0xffffffff")
	if !strings.Contains(ct, fmt.Sprintf("mark=%d", c.Settings.ConnMark(1)|0x80010002)) {
		t.Fatalf("VPN connmark lost QoS classification or policy ownership: %s", ct)
	}
	counters := sh(t, "iptables -t mangle -nvxL TEST_QOS")
	seen := false
	for _, line := range strings.Split(counters, "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[2] == "RETURN" && f[0] != "0" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("VPN egress lost QoS classification:\n%s", counters)
	}
	sh(t, "ipset del SNK_1_d4 203.0.113.80")
	runClient("WAN with QoS enabled")
	ct = sh(t, "conntrack -L -p tcp -s 192.168.77.2 -d 203.0.113.80 --mark 0x80010002/0xffffffff")
	if !strings.Contains(ct, fmt.Sprintf("mark=%d", uint32(0x80010002))) {
		t.Fatalf("WAN connmark lost QoS classification or acquired policy ownership: %s", ct)
	}
}
