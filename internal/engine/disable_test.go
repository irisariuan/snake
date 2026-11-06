package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

func countCmds(r *system.Recorder, prefix string) int {
	n := 0
	for _, c := range r.Commands {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestDisableEnable(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, KillSwitch: true,
		Domains: []string{"example.com"}, Leak: config.Leak{IPv6: "off", WebRTC: "off"}}}
	c.Settings.PreResolve = false
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{Responses: map[string]string{"ipset list -n": "SNK_1_d4\nother\n"}}
	p := DefaultPaths(dir)
	e := New(p, rec)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply("test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.DNSMasq); err != nil {
		t.Fatalf("apply should write the dnsmasq fragment: %v", err)
	}

	if err := e.Disable("test"); err != nil {
		t.Fatal(err)
	}
	if !e.Disabled() || !e.Status().Disabled {
		t.Fatal("not disabled")
	}
	if _, err := os.Stat(p.Disabled); err != nil {
		t.Fatalf("flag file missing: %v", err)
	}
	if _, err := os.Stat(p.DNSMasq); !os.IsNotExist(err) {
		t.Fatal("dnsmasq fragment should be removed")
	}
	if countCmds(rec, "ipset destroy SNK_1_d4") == 0 {
		t.Fatalf("sets not destroyed: %v", rec.Commands)
	}
	if countCmds(rec, "ipset destroy other") != 0 {
		t.Fatal("destroyed a set that is not snake's")
	}

	// While disabled, applies (hooks, health changes, config saves) do nothing.
	before := len(rec.Commands)
	if err := e.Apply("firewall hook"); err != nil {
		t.Fatal(err)
	}
	if len(rec.Commands) != before {
		t.Fatalf("apply ran commands while disabled: %v", rec.Commands[before:])
	}

	// The flag survives a restart.
	if !New(p, rec).Disabled() {
		t.Fatal("a new engine should start disabled")
	}

	if err := e.Enable("test"); err != nil {
		t.Fatal(err)
	}
	if e.Disabled() {
		t.Fatal("still disabled")
	}
	if _, err := os.Stat(p.Disabled); !os.IsNotExist(err) {
		t.Fatal("flag file should be gone")
	}
	if _, err := os.Stat(p.DNSMasq); err != nil {
		t.Fatalf("enable should re-apply: %v", err)
	}
}

func TestDoHSetHoldsOnlyResolverAddresses(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Policies = []config.Policy{{Name: "p", Enabled: true, Tunnels: []string{"wgc1"}, Domains: []string{"example.com"},
		Leak: config.Leak{BlockDoH: true, IPv6: "off", WebRTC: "off"}}}
	c.Normalize()
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{}
	e := New(DefaultPaths(dir), rec)
	e.DryRun = true
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply("test"); err != nil {
		t.Fatal(err)
	}
	// Replaced (flush + exact members), so addresses learned by older
	// versions, such as Google front ends, are dropped.
	var restore string
	for _, cmd := range rec.Commands {
		if strings.Contains(cmd, "ipset -exist restore") && strings.Contains(cmd, "SNK_DOH4") {
			restore = cmd
		}
	}
	if restore == "" || !strings.Contains(restore, "flush SNK_DOH4") || !strings.Contains(restore, "add SNK_DOH4_t 8.8.8.8") {
		t.Fatalf("DoH set not replaced with the resolver list:\n%v", rec.Commands)
	}
}
