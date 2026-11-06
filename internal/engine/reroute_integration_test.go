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
)

// TestIntegrationNoMidFlowReroute: a connection that started on WAN must stay
// on WAN when its destination joins a policy set mid-flow (e.g. a shared CDN
// address answered for a policy domain). Moving it would send packets with
// the WAN NAT binding into the tunnel, and the connection would stall.
func TestIntegrationNoMidFlowReroute(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 needed for the test client/server")
	}
	t.Cleanup(func() {
		_ = exec.Command("sh", "-c", "ip netns del snakelan; ip netns del snakesrv; ip link del lanv; ip link del wanv; ip link del br0; ip link del wgc1; "+
			"iptables -t nat -D POSTROUTING -o wanv -j MASQUERADE; for s in $(ipset list -n | grep ^SNK_); do ipset flush $s; done").Run()
	})
	if exec.Command("ip", "netns", "add", "snakelan").Run() != nil || exec.Command("ip", "netns", "add", "snakesrv").Run() != nil {
		t.Skip("cannot create network namespaces")
	}
	sh(t, "ip link set lo up; sysctl -qw net.ipv4.ip_forward=1")
	sh(t, "ip link add br0 type bridge; ip link set br0 up; ip addr add 192.168.77.1/24 dev br0")
	sh(t, "ip tuntap add mode tun dev wgc1; ip link set wgc1 up") // the tunnel swallows everything
	// LAN client
	sh(t, "ip link add lanv type veth peer name lanc; ip link set lanc netns snakelan; ip link set lanv master br0; ip link set lanv up")
	sh(t, "ip netns exec snakelan sh -c 'ip link set lo up; ip addr add 192.168.77.2/24 dev lanc; ip link set lanc up; ip route add default via 192.168.77.1'")
	// WAN with a server behind it
	sh(t, "ip link add wanv type veth peer name wans; ip link set wans netns snakesrv; ip addr add 198.18.0.1/30 dev wanv; ip link set wanv up")
	sh(t, "ip netns exec snakesrv sh -c 'ip link set lo up; ip addr add 198.18.0.2/30 dev wans; ip addr add 203.0.113.80/32 dev lo; ip link set wans up; ip route add default via 198.18.0.1'")
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
	if err := e.Apply("reroute test"); err != nil {
		t.Fatal(err)
	}

	// Client: one connection; line 1 before, line 2 after the address
	// joins the policy set (signalled through a file).
	flag := filepath.Join(dir, "go")
	time.Sleep(300 * time.Millisecond)
	cli := exec.Command("ip", "netns", "exec", "snakelan", "python3", "-c", `
import socket, os, time, sys
c = socket.create_connection(("203.0.113.80", 80), timeout=3); f = c.makefile("rwb")
f.write(b"one\n"); f.flush(); print("1:" + f.readline().decode().strip(), flush=True)
while not os.path.exists(sys.argv[1]): time.sleep(0.05)
try:
    f.write(b"two\n"); f.flush(); print("2:" + f.readline().decode().strip(), flush=True)
except Exception as e:
    print("2:stalled " + type(e).__name__, flush=True)
`, flag)
	out := &strings.Builder{}
	cli.Stdout, cli.Stderr = out, out
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "1:") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "1:one") {
		_ = cli.Process.Kill()
		t.Fatalf("connection over WAN did not work: %q", out.String())
	}
	sh(t, "ipset add SNK_1_d4 203.0.113.80") // e.g. a shared CDN address answered for a policy domain
	_ = os.WriteFile(flag, nil, 0o600)
	_ = cli.Wait()
	if !strings.Contains(out.String(), "2:two") {
		t.Errorf("established WAN connection broke when its address joined the policy set: %q", out.String())
	}
	// A new connection to that address now follows the policy (the tunnel
	// swallows it here, so it must not connect).
	nc := exec.Command("ip", "netns", "exec", "snakelan", "python3", "-c",
		`import socket; socket.create_connection(("203.0.113.80", 80), timeout=1)`)
	if err := nc.Run(); err == nil {
		t.Error("new connection reached the server over WAN instead of following the policy")
	}

	// Broadcom acceleration can expose WAN packets as UNTRACKED. Even
	// though the destination now matches a policy, these packets must keep
	// using WAN. v1.0.5 matched them as fresh traffic and sent them into
	// the tunnel. Force that state with the raw-table NOTRACK target and
	// count real packets after the routing decision.
	sh(t, "iptables -t raw -A PREROUTING -i br0 -p udp --dport 19999 -j CT --notrack")
	defer exec.Command("sh", "-c", "iptables -t raw -D PREROUTING -i br0 -p udp --dport 19999 -j CT --notrack").Run()
	sh(t, "iptables -t mangle -N TEST_WAN; iptables -t mangle -A TEST_WAN -m conntrack --ctstate UNTRACKED -j RETURN; iptables -t mangle -A POSTROUTING -o wanv -p udp --dport 19999 -j TEST_WAN")
	defer exec.Command("sh", "-c", "iptables -t mangle -D POSTROUTING -o wanv -p udp --dport 19999 -j TEST_WAN; iptables -t mangle -F TEST_WAN; iptables -t mangle -X TEST_WAN").Run()
	sh(t, `ip netns exec snakelan python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"wan affinity", ("203.0.113.80", 19999))'`)
	counters := sh(t, "iptables -t mangle -nvxL TEST_WAN")
	seen := false
	for _, line := range strings.Split(counters, "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[2] == "RETURN" && f[0] != "0" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("untracked WAN packet was rerouted into the tunnel:\n%s", counters)
	}
}
