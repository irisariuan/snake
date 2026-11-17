//go:build integration

package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/netfilter"
)

// TestIntegrationQUICRules applies a sniffing policy with the real tools:
// QUIC is read from the raw table (queue, flow set, mangle rule) instead of
// rejected, and turning sniffing off removes it all again.
func TestIntegrationQUICRules(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run as root inside `unshare -n`")
	}
	sh(t, "ip link set lo up")
	sh(t, "ip link show br0 >/dev/null 2>&1 || ip link add br0 type bridge; ip link set br0 up")
	sh(t, "ip link show wgc1 >/dev/null 2>&1 || ip tuntap add mode tun dev wgc1; ip link set wgc1 up")
	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "tv", Enabled: true, Tunnels: []string{"wgc1"}, Domains: []string{"example.tv"},
		Leak: config.Leak{IPv6: "off", WebRTC: "off", SniffSNI: true}}}
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
	if !e.caps.NFQueue || !e.caps.Raw {
		t.Skip("kernel without NFQUEUE or the raw table")
	}
	e.SeedHealth()
	e.decide()
	if err := e.Apply("quic test"); err != nil {
		t.Fatal(err)
	}
	defer e.sni.Stop()
	if err := e.Apply("quic test (idempotent)"); err != nil {
		t.Fatal(err)
	}
	if !e.sni.QUICRunning() {
		t.Fatal("QUIC queue not running")
	}
	q := c.Settings.QUICQueue()
	save := sh(t, "iptables-save")
	for _, s := range []string{
		"-A PREROUTING -j SNAKE_RAW",
		"-A SNAKE_RAW -i br+ -p udp -m udp --dport 443 -m set ! --match-set SNK_QF4 src,src,dst -j NFQUEUE --queue-num " + strconv.Itoa(q) + " --queue-bypass",
		"-A SNAKE -p udp -m udp --dport 443 -m conntrack --ctstate ESTABLISHED -m set ! --match-set SNK_QF4 src,src,dst -j SET --add-set SNK_QF4 src,src,dst",
	} {
		if !strings.Contains(save, s) {
			t.Errorf("iptables-save missing %q:\n%s", s, save)
		}
	}
	if strings.Contains(save, "--dport 443 -m connmark --mark 0x0/") {
		t.Error("QUIC still rejected")
	}
	if n := strings.Count(save, "-A PREROUTING -j SNAKE_RAW\n"); n != 1 {
		t.Errorf("raw hook installed %d times", n)
	}
	if !strings.Contains(sh(t, "ipset list -n"), netfilter.QUICFlowSet4) {
		t.Error("QUIC flow set missing")
	}
	if st := e.sni.Stats(); st.QUICQueue != q {
		t.Errorf("stats %+v", st)
	}

	// Sniffing off: no queue, no flow set.
	if _, err := e.UpdateConfig(func(c *config.Config) error { c.Policies[0].Leak.SniffSNI = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply("sniffing off"); err != nil {
		t.Fatal(err)
	}
	save = sh(t, "iptables-save")
	if strings.Contains(save, "NFQUEUE --queue-num "+strconv.Itoa(q)) || strings.Contains(save, "SNK_QF4") {
		t.Errorf("QUIC rules left:\n%s", save)
	}
	if strings.Contains(sh(t, "ipset list -n"), netfilter.QUICFlowSet4) {
		t.Error("QUIC flow set left")
	}
	if e.sni.QUICRunning() {
		t.Error("QUIC queue still open")
	}

	// Teardown removes the raw hook and chain.
	netfilter.Applier{R: e.R}.Teardown(false, c.Settings.LANInterfaces)
	if s := sh(t, "iptables-save -t raw"); strings.Contains(s, "SNAKE_RAW") {
		t.Errorf("raw table after teardown:\n%s", s)
	}
}
