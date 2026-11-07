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
	"github.com/irisariuan/snake/internal/match"
)

// TestIntegrationExcludedDevice: with real packets, an excluded device is
// neither routed into the tunnel nor blocked by the policy's drop: rules,
// while another device on the same LAN is.
// TestIntegrationRouteCondition: with real packets and the kernel's
// connection table, route:A;if:B starts a session for a device only while
// it has a live connection to B's address.
func TestIntegrationRouteCondition(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 needed for the test clients/server")
	}
	t.Cleanup(func() {
		_ = exec.Command("sh", "-c", "ip netns del snakea; ip netns del snakeb; ip netns del snakesrv; ip link del lanva; ip link del lanvb; ip link del wanv; ip link del br0; ip link del wgc1; "+
			"iptables -t nat -D POSTROUTING -o wanv -j MASQUERADE; for s in $(ipset list -n | grep ^SNK_); do ipset flush $s; done").Run()
	})
	for _, ns := range []string{"snakea", "snakeb", "snakesrv"} {
		if exec.Command("ip", "netns", "add", ns).Run() != nil {
			t.Skip("cannot create network namespaces")
		}
	}
	sh(t, "ip link set lo up; sysctl -qw net.ipv4.ip_forward=1")
	sh(t, "ip link add br0 type bridge; ip link set br0 up; ip addr add 192.168.77.1/24 dev br0")
	sh(t, "ip tuntap add mode tun dev wgc1; ip link set wgc1 up") // the tunnel swallows everything
	for i, ns := range []string{"snakea", "snakeb"} {
		v, c, ip := "lanv"+ns[5:], "lanc", []string{"192.168.77.2", "192.168.77.3"}[i]
		sh(t, "ip link add "+v+" type veth peer name "+c+"; ip link set "+c+" netns "+ns+"; ip link set "+v+" master br0; ip link set "+v+" up")
		sh(t, "ip netns exec "+ns+" sh -c 'ip link set lo up; ip addr add "+ip+"/24 dev lanc; ip link set lanc up; ip route add default via 192.168.77.1'")
	}
	sh(t, "ip link add wanv type veth peer name wans; ip link set wans netns snakesrv; ip addr add 198.18.0.1/30 dev wanv; ip link set wanv up")
	sh(t, "ip netns exec snakesrv sh -c 'ip link set lo up; ip addr add 198.18.0.2/30 dev wans; ip addr add 203.0.113.80/32 dev lo; ip addr add 203.0.113.81/32 dev lo; ip link set wans up; ip route add default via 198.18.0.1'")
	sh(t, "ip route add 203.0.113.80 via 198.18.0.2; ip route add 203.0.113.81 via 198.18.0.2; iptables -t nat -A POSTROUTING -o wanv -j MASQUERADE")
	srv := exec.Command("ip", "netns", "exec", "snakesrv", "python3", "-c", `
import socket, threading
def held():
    h = socket.socket(); h.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); h.bind(("0.0.0.0", 8080)); h.listen()
    conns = []
    while True:
        c, _ = h.accept(); conns.append(c)  # kept open
threading.Thread(target=held, daemon=True).start()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 80)); s.listen()
while True:
    c, _ = s.accept(); c.sendall(b"hi"); c.close()
`)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()

	rule := "route:**.cdn.example;if:trigger.example"
	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true,
		Domains: []string{rule}, Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
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
	if err := e.Apply("route test"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	get := func(ns, ip string) bool {
		return exec.Command("ip", "netns", "exec", ns, "python3", "-c",
			`import socket; c = socket.create_connection(("`+ip+`", 80), timeout=1.5); assert c.recv(2) == b"hi"`).Run() == nil
	}
	// The DNS inspector saw trigger.example answered with .81.
	p := e.runtime().Policies[0]
	e.recordCond(p.ID, []string{"203.0.113.81"}, e.domainSet(p).CondHits("www.trigger.example"))
	route := func(client string) bool {
		ok, err := e.RouteSessions(p.ID, client, []string{"203.0.113.80"}, rule, "a.cdn.example", match.Opts{})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if route("192.168.77.2") {
		t.Fatal("condition held before any connection to the trigger")
	}
	// Device A keeps a connection to the trigger site open.
	hold := exec.Command("ip", "netns", "exec", "snakea", "python3", "-c",
		`import socket, time; c = socket.create_connection(("203.0.113.81", 8080), timeout=2); print("up", flush=True); time.sleep(30)`)
	out := &strings.Builder{}
	hold.Stdout = out
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	defer hold.Process.Kill()
	for i := 0; i < 30 && !strings.Contains(out.String(), "up"); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if !route("192.168.77.2") {
		t.Fatal("condition did not hold with a live connection to the trigger")
	}
	if route("192.168.77.3") {
		t.Error("condition held for a device without a connection to the trigger")
	}
	if get("snakea", "203.0.113.80") {
		t.Error("route session did not send device A into the tunnel")
	}
	if !get("snakeb", "203.0.113.80") {
		t.Error("device B was routed")
	}
}
