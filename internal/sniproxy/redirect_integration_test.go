//go:build integration

package sniproxy

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/match"
)

// TestIntegrationRedirect sends a connection through a real iptables
// REDIRECT: the proxy must recover the original destination and dial it
// with the matching policy's mark. Needs root and iptables:
//
//	SNAKE_INTEGRATION=1 go test -tags integration ./internal/sniproxy -run Integration
func TestIntegrationRedirect(t *testing.T) {
	if os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1")
	}
	t.Run("ipv4", func(t *testing.T) { testRedirect(t, "iptables", "tcp4", "127.0.0.2") })
	t.Run("ipv6", func(t *testing.T) { testRedirect(t, "ip6tables", "tcp6", "::1") })
}

func testRedirect(t *testing.T, iptables, network, host string) {
	srv, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("no %s: %v", network, err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	srvPort := strconv.Itoa(srv.Addr().(*net.TCPAddr).Port)

	// A fixed free port: both listeners share it.
	pl, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	pport := strconv.Itoa(pl.Addr().(*net.TCPAddr).Port)
	pl.Close()
	p := &Proxy{}
	if err := p.Configure(Config{Port: pl.Addr().(*net.TCPAddr).Port, IPv6: true, Policies: []Policy{{ID: 1, Name: "nf", Set: match.MustCompile([]string{"netflix.com"}), Mark: 0x10000}}}); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	// Locally generated connections to the server are redirected to the
	// proxy, except the proxy's own marked upstream connection. Unmarked
	// upstream connections would loop, so only the matched case is tested.
	rule := []string{"-t", "nat", "OUTPUT", "-p", "tcp", "-d", host, "--dport", srvPort, "-m", "mark", "!", "--mark", "0x10000", "-j", "REDIRECT", "--to-ports", pport}
	ipt := func(op string) error {
		args := append([]string{rule[0], rule[1], op}, rule[2:]...)
		out, err := exec.Command(iptables, args...).CombinedOutput()
		if err != nil {
			t.Logf("iptables %v: %s", args, out)
		}
		return err
	}
	if err := ipt("-A"); err != nil {
		t.Skip("iptables REDIRECT unavailable")
	}
	defer ipt("-D")
	// Count the proxy's marked upstream connections.
	mrule := []string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", host, "--dport", srvPort, "-m", "mark", "--mark", "0x10000", "-j", "ACCEPT"}
	if out, err := exec.Command(iptables, mrule...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	defer func() { mrule[2] = "-D"; _ = exec.Command(iptables, mrule...).Run() }()

	c, err := net.Dial(network, srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello := buildHello(sniExt("www.netflix.com"))
	if _, err := c.Write(append(hello, "ping"...)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(hello)+4)
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, append(hello, "ping"...)) {
		t.Fatalf("relay through REDIRECT: %v", err)
	}
	st := p.Stats()
	if st.Matched != 1 || st.Refused != 0 || st.Errors != 0 {
		t.Fatalf("stats %+v", st)
	}
	// The upstream SYN carried the policy mark.
	out, _ := exec.Command(iptables, "-t", "nat", "-L", "OUTPUT", "-vnx").CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) > 2 && f[2] == "ACCEPT" && strings.Contains(l, "dpt:"+srvPort) && strings.HasSuffix(l, "mark match 0x10000") {
			if f[0] != "1" {
				t.Fatalf("marked upstream connections: %s\n%s", f[0], out)
			}
			return
		}
	}
	t.Fatalf("marked rule missing:\n%s", out)
}
