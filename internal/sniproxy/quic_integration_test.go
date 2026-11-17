//go:build integration

package sniproxy

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/irisariuan/snake/internal/match"
)

// TestIntegrationQUIC sends QUIC Initial packets from a client namespace
// through this one (the router) to a server namespace, with the rules
// snake installs: the raw-table queue, the flow set kept by mangle, a
// policy set routing rule and NAT. A ClientHello split over two packets
// must arrive at the server as one flow (both packets, one NAT mapping)
// marked by the policy's set, which the proxy filled before releasing
// them; once the server replied, the flow's packets skip the queue.
//
//	SNAKE_INTEGRATION=1 unshare -n go test -tags integration ./internal/sniproxy -run IntegrationQUIC
func TestIntegrationQUIC(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	sh := func(cmd string) string {
		t.Helper()
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		return string(out)
	}
	for _, ns := range []string{"snkc", "snks"} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		sh("ip netns add " + ns)
		defer exec.Command("ip", "netns", "del", ns).Run()
	}
	sh(`ip link set lo up; sysctl -qw net.ipv4.ip_forward=1
ip link add rc0 type veth peer name c0 netns snkc
ip link add rs0 type veth peer name s0 netns snks
ip addr add 10.1.0.1/24 dev rc0; ip link set rc0 up
ip addr add 10.2.0.1/24 dev rs0; ip link set rs0 up
ip -n snkc addr add 10.1.0.2/24 dev c0; ip -n snkc link set c0 up; ip -n snkc link set lo up; ip -n snkc route add default via 10.1.0.1
ip -n snks addr add 10.2.0.2/24 dev s0; ip -n snks addr add 10.2.0.3/24 dev s0; ip -n snks link set s0 up; ip -n snks link set lo up; ip -n snks route add default via 10.2.0.1`)
	const queue = 4455
	sh(fmt.Sprintf(`ipset create QF hash:ip,port,ip timeout 120
ipset create POL hash:net timeout 600
iptables -t raw -A PREROUTING -i rc0 -p udp --dport 443 -m set ! --match-set QF src,src,dst -j NFQUEUE --queue-num %d --queue-bypass
iptables -t mangle -A PREROUTING -i rc0 -p udp --dport 443 -m conntrack --ctstate ESTABLISHED -m set ! --match-set QF src,src,dst -j SET --add-set QF src,src,dst
iptables -t mangle -A PREROUTING -i rc0 -m conntrack --ctstate NEW -m set --match-set POL dst -j CONNMARK --set-mark 0x20000
iptables -t mangle -A PREROUTING -i rc0 -j CONNMARK --restore-mark
iptables -t mangle -A FORWARD -i rc0 -m mark --mark 0x20000 -j ACCEPT
iptables -t nat -A POSTROUTING -o rs0 -j MASQUERADE`, queue))
	defer exec.Command("sh", "-c", "iptables -t raw -F; iptables -t mangle -F; iptables -t nat -F; ipset destroy QF; ipset destroy POL").Run()

	p := &Proxy{Sets: execSets{}}
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	port := pl.Addr().(*net.TCPAddr).Port
	pl.Close()
	if err := p.Configure(Config{Port: port, QUICQueue: queue, MarkMask: 0x00ff0000, Policies: []Policy{{
		ID: 2, Name: "tv", Set: match.MustCompile([]string{"example.tv"}), Mark: 0x20000, Set4: "POL"}}}); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	server := inNetns(t, "snks", func() (net.PacketConn, error) { return net.ListenPacket("udp4", "10.2.0.2:443") })
	defer server.Close()
	server2 := inNetns(t, "snks", func() (net.PacketConn, error) { return net.ListenPacket("udp4", "10.2.0.3:443") })
	defer server2.Close()
	client := inNetns(t, "snkc", func() (net.PacketConn, error) { return net.ListenPacket("udp4", "10.1.0.2:0") })
	defer client.Close()
	srvAddr := &net.UDPAddr{IP: net.ParseIP("10.2.0.2"), Port: 443}

	type rx struct {
		from string
		n    int
	}
	got := make(chan rx, 16)
	for _, srv := range []net.PacketConn{server, server2} {
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := srv.ReadFrom(buf)
				if err != nil {
					return
				}
				got <- rx{from.String(), n}
			}
		}()
	}
	recv := func(n int) []rx {
		t.Helper()
		var out []rx
		timeout := time.After(3 * time.Second)
		for len(out) < n {
			select {
			case r := <-got:
				out = append(out, r)
			case <-timeout:
				t.Fatalf("server got %d of %d datagrams: %+v", len(out), n, out)
			}
		}
		return out
	}

	pkts := splitInitials(t, quicV1, 1, []byte{0xab, 0xcd, 0xef, 1, 2, 3, 4, 5}, quicHello(t, "play.example.tv"), 700, rand.New(rand.NewSource(3)))
	if len(pkts) < 2 {
		t.Fatalf("ClientHello in %d packets", len(pkts))
	}
	for _, d := range pkts {
		if _, err := client.WriteTo(d, srvAddr); err != nil {
			t.Fatal(err)
		}
	}
	first := recv(len(pkts))
	for _, r := range first[1:] {
		if r.from != first[0].from {
			t.Fatalf("one flow, two NAT mappings: %+v", first)
		}
	}
	if !strings.Contains(sh("ipset list POL"), "10.2.0.2") {
		t.Fatal("destination not learned")
	}
	// Every packet was routed by the policy's set from the first one.
	if n := counter(t, "mangle", "FORWARD", "0x20000"); n != len(pkts) {
		t.Errorf("%d of %d packets marked by the policy", n, len(pkts))
	}

	// The server answers; the client's next packet establishes the flow
	// (into QF), and later ones skip the queue.
	from, _ := net.ResolveUDPAddr("udp4", first[0].from)
	if _, err := server.WriteTo([]byte{0xc0, 0, 0, 0, 1}, from); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if _, err := client.WriteTo(append([]byte{0x41}, make([]byte, 60)...), srvAddr); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond) // packets sent together are all queued before QF knows the flow
	}
	recv(3)
	if !strings.Contains(sh("ipset list QF"), "10.1.0.2,udp:") {
		t.Errorf("flow not in QF:\n%s", sh("ipset list QF"))
	}
	queued := counter(t, "raw", "PREROUTING", "NFQUEUE")
	if queued > len(pkts)+1 {
		t.Errorf("%d packets queued, want at most %d (the Initials and one before QF knew the flow)", queued, len(pkts)+1)
	}

	// A flow to a name no policy has, at another address, goes on
	// unmarked.
	other := inNetns(t, "snkc", func() (net.PacketConn, error) { return net.ListenPacket("udp4", "10.1.0.2:0") })
	defer other.Close()
	op := splitInitials(t, quicV1, 1, []byte{9, 8, 7, 6}, quicHello(t, "www.example.org"), 700, rand.New(rand.NewSource(4)))
	for _, d := range op {
		_, _ = other.WriteTo(d, &net.UDPAddr{IP: net.ParseIP("10.2.0.3"), Port: 443})
	}
	recv(len(op))
	if strings.Contains(sh("ipset list POL"), "10.2.0.3") {
		t.Error("unmatched destination learned")
	}
	if n := counter(t, "mangle", "FORWARD", "0x20000"); n != len(pkts)+3 {
		t.Errorf("marked packets %d, want %d (unmatched flow marked?)", n, len(pkts)+3)
	}
	if st := p.Stats(); st.QUIC != 2 || st.Matched != 1 {
		t.Errorf("stats %+v", st)
	}
}

type execSets struct{}

func (execSets) AddMany(name string, entries []string) error {
	for _, e := range entries {
		if out, err := exec.Command("ipset", "-exist", "add", name, e).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
	}
	return nil
}

// inNetns opens a socket inside a named network namespace.
func inNetns(t *testing.T, ns string, open func() (net.PacketConn, error)) net.PacketConn {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	target, err := os.Open("/run/netns/" + ns)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setns(int(self.Fd()), unix.CLONE_NEWNET); err != nil {
			panic(err)
		}
	}()
	c, err := open()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// counter returns the packet count of the first rule in table/chain whose
// listing contains match.
func counter(t *testing.T, table, chain, match string) int {
	t.Helper()
	out, err := exec.Command("iptables", "-t", table, "-L", chain, "-vnx").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) > 2 && strings.Contains(l, match) {
			var n int
			fmt.Sscan(f[0], &n)
			return n
		}
	}
	t.Fatalf("no rule with %q in %s %s:\n%s", match, table, chain, out)
	return 0
}
