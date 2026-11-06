package engine

import (
	"fmt"
	"os"
	"time"

	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/routing"
)

// Emergency disable: snake removes every rule, route, set and dnsmasq
// option it installed, so the router behaves as if snake were not installed
// (all traffic uses the normal WAN connection, kill switches included). The
// daemon keeps running so the web UI and API stay reachable to turn it back
// on. The state is kept in a flag file, so it survives restarts and reboots.

// Disabled reports whether snake is in emergency-disabled mode.
func (e *Engine) Disabled() bool { return e.disabled.Load() }

// DisabledSince is when snake was disabled (zero when enabled).
func (e *Engine) DisabledSince() time.Time {
	if !e.Disabled() {
		return time.Time{}
	}
	if fi, err := os.Stat(e.P.Disabled); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

// Disable removes all of snake's kernel and dnsmasq state and stops applying
// until Enable is called.
func (e *Engine) Disable(reason string) error {
	if e.Disabled() {
		return nil
	}
	// Persist learned addresses first so Enable can bring them back.
	e.saveSets()

	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	if !e.DryRun && e.P.Disabled != "" {
		if err := os.WriteFile(e.P.Disabled, []byte(time.Now().Format(time.RFC3339)+" "+reason+"\n"), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", e.P.Disabled, err)
		}
	}
	e.disabled.Store(true)

	e.mu.Lock()
	cfg, caps := e.rt, e.caps
	e.mu.Unlock()
	lan := "br+"
	if cfg != nil && cfg.Settings.LANInterfaces != "" {
		lan = cfg.Settings.LANInterfaces
	}
	// Firewall first: the DNS and WebRTC queue rules must be gone before
	// their listeners stop, or queued packets would be dropped.
	netfilter.Applier{R: e.R}.Teardown(caps.IPv6, lan)
	routing.Manager{R: e.R}.Teardown(caps.IPv6)
	if !e.DryRun && e.isDaemon() {
		e.dns.Stop()
		e.rtc.Stop()
		e.fwd.Stop()
	}
	ips := e.ipset()
	for _, n := range ips.Names() {
		_ = ips.Destroy(n)
	}
	if !e.DryRun {
		if err := os.Remove(e.P.DNSMasq); err == nil {
			if _, err := e.R.Run("service", "restart_dnsmasq"); err != nil {
				logx.Warnf("disable: restart dnsmasq: %v", err)
			}
		}
	}

	e.mu.Lock()
	e.plan = netfilter.Plan{}
	e.dnsOn = false
	e.rtcKey = ""
	e.netHashes = map[string]string{}
	e.lastError = ""
	e.mu.Unlock()
	e.learnRoute.Store(map[string]int{})
	e.event("", "disable", "snake DISABLED (%s): all rules removed, traffic uses WAN", reason)
	return nil
}

// Enable leaves emergency-disabled mode and re-applies the configuration.
func (e *Engine) Enable(reason string) error {
	if !e.Disabled() {
		return nil
	}
	e.applyMu.Lock()
	if !e.DryRun && e.P.Disabled != "" {
		if err := os.Remove(e.P.Disabled); err != nil && !os.IsNotExist(err) {
			e.applyMu.Unlock()
			return fmt.Errorf("remove %s: %w", e.P.Disabled, err)
		}
	}
	e.disabled.Store(false)
	e.applyMu.Unlock()

	if !e.DryRun {
		if _, err := os.Stat(e.P.IPSetSave); err == nil {
			if err := e.ipset().RestoreFile(e.P.IPSetSave); err != nil {
				logx.Warnf("enable: restore saved ipsets: %v", err)
			}
		}
	}
	e.event("", "enable", "snake enabled (%s)", reason)
	e.decide()
	err := e.Apply("enabled")
	e.Kick()
	go e.PreResolve()
	return err
}
