package engine

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

func freePort(t *testing.T) (int, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln.Addr().(*net.TCPAddr).Port, ln
}

func TestSNIProxyLifecycle(t *testing.T) {
	dir := t.TempDir()
	port, ln := freePort(t)
	ln.Close()
	c := config.Default()
	c.Settings.PreResolve = false
	c.Settings.SNIProxyPort = port
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true,
		Domains: []string{"example.com"}, Leak: config.Leak{IPv6: "off", WebRTC: "off", SniffSNI: true}}}
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{}
	e := New(DefaultPaths(dir), rec)
	e.daemon = true
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply("test"); err != nil {
		t.Fatal(err)
	}
	defer e.sni.Stop()
	if !e.sni.Running() {
		t.Fatal("proxy not running")
	}
	if n := e.Plan().Restore["4/nat"]; !strings.Contains(n, "-j REDIRECT --to-ports "+strconv.Itoa(port)) {
		t.Fatalf("no redirect:\n%s", n)
	}
	st := e.Status()
	if st.SNI == nil || st.SNI.Listen == "" || st.Policies[0].SNIMatched == nil {
		t.Fatalf("status: %+v", st.SNI)
	}
	lc := e.LeakChecks()
	if !strings.Contains(strings.Join(lc[0].OK, "\n"), "TLS server name") {
		t.Fatalf("leak checks: %+v", lc[0])
	}

	// A port that cannot be bound: no redirect, and the reason is shown.
	busy, bl := freePort(t)
	defer bl.Close()
	if _, err := e.UpdateConfig(func(c *config.Config) error { c.Settings.SNIProxyPort = busy; return nil }); err == nil {
		t.Fatal("bind error not reported")
	}
	if n := e.Plan().Restore["4/nat"]; strings.Contains(n, "REDIRECT --to-ports") {
		t.Fatalf("redirect without a proxy:\n%s", n)
	}
	if st := e.Status(); st.SNI == nil || !strings.Contains(st.SNI.LastError, "address already in use") {
		t.Fatalf("status: %+v", st.SNI)
	}

	// Sniffing off: the proxy stops.
	if _, err := e.UpdateConfig(func(c *config.Config) error {
		c.Settings.SNIProxyPort = port
		c.Policies[0].Leak.SniffSNI = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if e.sni.Running() || e.Status().SNI != nil {
		t.Fatal("proxy still running")
	}

	// Shutdown flushes the redirect before stopping the proxy.
	if _, err := e.UpdateConfig(func(c *config.Config) error { c.Policies[0].Leak.SniffSNI = true; return nil }); err != nil {
		t.Fatal(err)
	}
	e.stopSNI()
	if e.sni.Running() || countCmds(rec, "iptables -t nat -F SNAKE_SNI") == 0 {
		t.Fatalf("redirect not flushed: running=%v", e.sni.Running())
	}
}
