//go:build integration

package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsinspect"
)

func pct(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

func avg(d []time.Duration) time.Duration {
	var t time.Duration
	for _, x := range d {
		t += x
	}
	return t / time.Duration(len(d))
}

// TestIntegrationDNSLatency measures how much the DNS inspector adds to a
// client's lookup, with a large rule list, and how long the diagnostics
// paths take. It logs numbers; it only fails on gross regressions.
func TestIntegrationDNSLatency(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	sh(t, "ip link set lo up")
	sh(t, "ip link show br0 >/dev/null 2>&1 || ip link add br0 type bridge; ip link set br0 up")
	sh(t, "ip link show wgc1 >/dev/null 2>&1 || ip tuntap add mode tun dev wgc1; ip link set wgc1 up")
	stop := fakeDNSFunc(t, func(name string) []string {
		// q<N>.<zone> -> 198.18.<N/250>.<N%250+1>
		i := strings.IndexByte(name, '.')
		n, _ := strconv.Atoi(strings.TrimPrefix(name[:max(i, 0)], "q"))
		ip := fmt.Sprintf("198.18.%d.%d", n/250%250, n%250+1)
		if strings.HasSuffix(name, ".cdn.example") {
			return []string{"edge" + strconv.Itoa(n) + ".match.example", ip}
		}
		return []string{ip}
	})
	defer stop()

	rules := []string{"match.example", "**.akamai.example", `/^ipv4-c\d+-x\.example$/`, "~zzkeyword", "!=blocked.match.example"}
	for i := 0; i < 20000; i++ {
		rules = append(rules, fmt.Sprintf("dom%d.example", i))
	}
	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "big", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true, Domains: rules,
		Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
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
	if err := e.Apply("latency test"); err != nil {
		t.Fatal(err)
	}
	defer e.dns.Stop()

	run := func(label, zone string, from, n int) []time.Duration {
		var d []time.Duration
		for i := from; i < from+n; i++ {
			start := time.Now()
			if _, err := dnsinspect.Query("127.0.0.1:53", fmt.Sprintf("q%d.%s", i, zone), 3*time.Second); err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			d = append(d, time.Since(start))
		}
		t.Logf("%-34s avg %-10v p95 %-10v max %v", label, avg(d), pct(d, .95), pct(d, 1))
		return d
	}
	const n = 300
	newAddr := run("inspector, match, new address", "match.example", 0, n)
	run("inspector, match, cached address", "match.example", 0, n)
	run("inspector, CNAME match, new address", "cdn.example", n, n)
	noMatch := run("inspector, no match", "other.example", 0, n)
	if got := e.dns.Stats(); got.Added < 2*n {
		t.Errorf("added %d, want >= %d", got.Added, 2*n)
	}

	// Concurrent clients: answers must not queue behind each other.
	parallel := func(label string, from int, zone string) {
		start := time.Now()
		done := make(chan time.Duration, 64)
		for w := 0; w < 64; w++ {
			go func(w int) {
				s := time.Now()
				_, _ = dnsinspect.Query("127.0.0.1:53", fmt.Sprintf("q%d.%s", from+w, zone), 3*time.Second)
				done <- time.Since(s)
			}(w)
		}
		var par []time.Duration
		for w := 0; w < 64; w++ {
			par = append(par, <-done)
		}
		t.Logf("%-34s avg %-10v p95 %-10v max %v (wall %v)", label, avg(par), pct(par, .95), pct(par, 1), time.Since(start))
	}
	parallel("64 parallel new addresses", 10000, "match.example")
	parallel("64 parallel unrouted", 10000, "other.example")

	e.dns.Stop()
	base := run("no inspector", "other.example", n, n)
	parallel("64 parallel, no inspector", 20000, "other.example")
	t.Logf("inspector overhead: no match %v, new address %v", avg(noMatch)-avg(base), avg(newAddr)-avg(base))
	if !e.caps.IPSetNetlink {
		t.Error("ipset netlink not in use")
	}
	if over := avg(noMatch) - avg(base); over > 5*time.Millisecond {
		t.Errorf("inspector adds %v to lookups of unrouted names", over)
	}

	// Diagnostics paths.
	s := time.Now()
	dt := e.TestDomain("q5.match.example")
	t.Logf("TestDomain: %v (policy %q)", time.Since(s), dt.Policy)
	sh(t, "for i in $(seq 0 199); do for j in $(seq 1 250); do echo add SNK_1_d4 10.$((i/250)).$i.$j; done; done | ipset -exist restore")
	s = time.Now()
	sh(t, "ipset list SNK_1_d4 >/dev/null")
	t.Logf("ipset list alone: %v", time.Since(s))
	s = time.Now()
	v, err := e.LearnedAddrs("big", LearnedDNS, "", 0)
	t.Logf("LearnedAddrs over %d entries: %v (err %v)", v.Total, time.Since(s), err)
	s = time.Now()
	v, _ = e.LearnedAddrs("big", LearnedDNS, "198.18.0.5", 0)
	t.Logf("LearnedAddrs filtered: %v (%d matching)", time.Since(s), v.Matching)
}
