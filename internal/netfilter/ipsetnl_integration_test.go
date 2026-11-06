//go:build integration

package netfilter

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/system"
)

func TestIntegrationIPSetNetlink(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	run := func(c string) string {
		out, err := exec.Command("sh", "-c", c).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", c, err, out)
		}
		return string(out)
	}
	run("ipset destroy NLT4 2>/dev/null; ipset destroy NLT6 2>/dev/null; ipset create NLT4 hash:net timeout 600; ipset create NLT6 hash:ip family inet6")
	defer exec.Command("sh", "-c", "ipset destroy NLT4; ipset destroy NLT6").Run()
	nl, err := OpenNL()
	if err != nil {
		t.Fatal(err)
	}
	defer nl.Close()
	if err := nl.Add("NLT4", []net.IP{net.ParseIP("203.0.113.5"), net.ParseIP("203.0.113.6")}); err != nil {
		t.Fatal(err)
	}
	// re-add refreshes instead of failing
	run("ipset -exist add NLT4 203.0.113.5 timeout 5")
	if err := nl.Add("NLT4", []net.IP{net.ParseIP("203.0.113.5")}); err != nil {
		t.Fatal(err)
	}
	l := run("ipset list NLT4")
	var left int
	for _, line := range strings.Split(l, "\n") {
		if strings.HasPrefix(line, "203.0.113.5 timeout ") {
			left, _ = strconv.Atoi(strings.TrimPrefix(line, "203.0.113.5 timeout "))
		}
	}
	if left < 500 || !strings.Contains(l, "203.0.113.6") {
		t.Fatalf("re-add did not reset the timeout (%d):\n%s", left, l)
	}
	if err := nl.Add("NLT6", []net.IP{net.ParseIP("2001:db8::7")}); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"203.0.113.6": true, "203.0.113.9": false} {
		if in, err := nl.Test("NLT4", net.ParseIP(ip)); err != nil || in != want {
			t.Errorf("test %s = %v %v", ip, in, err)
		}
	}
	if in, err := nl.Test("NLT6", net.ParseIP("2001:db8::7")); err != nil || !in {
		t.Errorf("v6 test %v %v", in, err)
	}
	if err := nl.Add("NOPE", []net.IP{net.ParseIP("203.0.113.5")}); err == nil {
		t.Error("missing set accepted")
	}
	// IPSet uses it, and keeps working (CLI) for missing sets
	x := IPSet{R: system.Exec{Timeout: 5 * time.Second}, NL: nl}
	if err := x.AddMany("NLT4", []string{"198.51.100.1"}); err != nil || !x.Test("NLT4", "198.51.100.1") {
		t.Fatalf("IPSet via netlink: %v", err)
	}
	if err := x.AddMany("NOPE", []string{"198.51.100.1"}); err == nil {
		t.Error("missing set: no error")
	}
	if !nl.Usable() {
		t.Error("netlink disabled after a missing-set error")
	}

	const n = 200
	s := time.Now()
	for i := 0; i < n; i++ {
		_ = nl.Add("NLT4", []net.IP{net.IPv4(198, 18, 1, byte(i))})
	}
	tn := time.Since(s) / n
	cli := IPSet{R: system.Exec{Timeout: 5 * time.Second}}
	s = time.Now()
	for i := 0; i < n; i++ {
		_ = cli.AddMany("NLT4", []string{net.IPv4(198, 18, 2, byte(i)).String()})
	}
	tc := time.Since(s) / n
	t.Logf("per add: netlink %v, ipset tool %v (%.0fx)", tn, tc, float64(tc)/float64(tn))
}
