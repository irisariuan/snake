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
// TestIntegrationSessions: with real packets, a session routes an address
// into the tunnel for its device only, survives a full re-apply, and ends
// after its TTL; another device keeps reaching the address over WAN.
func TestIntegrationSessions(t *testing.T) {
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
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 80)); s.listen()
while True:
    c, _ = s.accept(); c.sendall(b"hi"); c.close()
`)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()

	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true,
		Domains: []string{"session:**.example.net"}, Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
	c.Settings.PreResolve = false
	c.Settings.LANInterfaces = "br0"
	c.Settings.SessionTTL = 60
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
	if err := e.Apply("session test"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	get := func(ns, ip string) bool {
		return exec.Command("ip", "netns", "exec", ns, "python3", "-c",
			`import socket; c = socket.create_connection(("`+ip+`", 80), timeout=1.5); assert c.recv(2) == b"hi"`).Run() == nil
	}
	if !get("snakea", "203.0.113.80") || !get("snakeb", "203.0.113.80") {
		t.Fatal("no session yet: both devices should reach the server over WAN")
	}
	// What the DNS inspector does when device A looks up a session name.
	if err := e.AddSessions(1, "192.168.77.2", []string{"203.0.113.80"}, SessionRule, "session:**.example.net", "cdn.example.net", match.Opts{}); err != nil {
		t.Fatal(err)
	}
	if get("snakea", "203.0.113.80") {
		t.Error("device with the session reached the server over WAN instead of the tunnel")
	}
	if !get("snakeb", "203.0.113.80") {
		t.Error("device without the session was routed into the tunnel")
	}
	if !get("snakea", "203.0.113.81") {
		t.Error("session routed another address")
	}
	// A full re-apply keeps the session.
	if err := e.Apply("session test again"); err != nil {
		t.Fatal(err)
	}
	if get("snakea", "203.0.113.80") {
		t.Error("session lost by a re-apply")
	}
	// share=: device A's session to .81 is routed for device B too.
	if err := e.AddSessions(1, "192.168.77.2", []string{"203.0.113.81"}, SessionRule, "session[share=192.168.77.3]:**.example.net", "b.example.net",
		match.Opts{Share: []string{"192.168.77.3"}}); err != nil {
		t.Fatal(err)
	}
	if get("snakea", "203.0.113.81") || get("snakeb", "203.0.113.81") {
		t.Error("shared session did not route both devices into the tunnel")
	}
	if !get("snakeb", "203.0.113.80") {
		t.Error("sharing one session routed the other for device B")
	}
	// Drop sessions (.82, .83: no session routes them).
	if _, err := e.UpdateConfig(func(c *config.Config) error {
		c.Policies[0].Domains = append(c.Policies[0].Domains, "drop[ttl=5m]:ads.example.net")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sh(t, "ip netns exec snakesrv sh -c 'ip addr add 203.0.113.82/32 dev lo; ip addr add 203.0.113.83/32 dev lo'; ip route add 203.0.113.82 via 198.18.0.2; ip route add 203.0.113.83 via 198.18.0.2")
	if !get("snakea", "203.0.113.82") || !get("snakeb", "203.0.113.82") {
		t.Fatal(".82 not reachable before the drop session")
	}
	// Device A looked up the dropped name: blocked for A only.
	if err := e.AddSessions(1, "192.168.77.2", []string{"203.0.113.82"}, SessionDrop, "drop[ttl=5m]:ads.example.net", "x.ads.example.net", match.Opts{TTL: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if get("snakea", "203.0.113.82") {
		t.Error("drop session did not block the device that looked the name up")
	}
	if !get("snakeb", "203.0.113.82") {
		t.Error("drop session blocked another device")
	}
	// The blocked attempt shows in the rule counters (renews the session).
	if !e.dropAttempts()[sessionKey{Policy: 1, Addr: "203.0.113.82"}] {
		t.Error("blocked attempt not seen in the drop session counters")
	}
	// Shared with B: blocked for both.
	if err := e.AddSessions(1, "192.168.77.2", []string{"203.0.113.83"}, SessionDrop, "drop[share=192.168.77.3]:ads.example.net", "y.ads.example.net",
		match.Opts{Share: []string{"192.168.77.3"}}); err != nil {
		t.Fatal(err)
	}
	if get("snakea", "203.0.113.83") || get("snakeb", "203.0.113.83") {
		t.Error("shared drop session did not block both devices")
	}
	// TTL over with no connection: the route ends.
	e.refreshSessions(strings.NewReader(""), time.Now().Add(2*time.Minute))
	if !get("snakea", "203.0.113.80") {
		t.Error("expired session still routes")
	}
}
