package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsfwd"
	"github.com/irisariuan/snake/internal/dnsinspect"
	"github.com/irisariuan/snake/internal/health"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/sniproxy"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/webrtc"
)

// Run is the daemon main loop.
func (e *Engine) Run(ctx context.Context) error {
	e.mu.Lock()
	e.daemon = true
	e.mu.Unlock()
	if err := e.Load(); err != nil {
		return err
	}
	e.DetectCaps()
	ips := e.ipset()
	if e.Disabled() {
		logx.Warnf("snake is DISABLED (emergency switch): not installing any rules; enable it in the web UI or with: snake enable")
	} else if _, err := os.Stat(e.P.IPSetSave); err == nil {
		if err := ips.RestoreFile(e.P.IPSetSave); err != nil {
			logx.Warnf("restore saved ipsets: %v", err)
		}
	}
	e.importLegacyServers()
	e.LoadDNSRecords()
	e.SeedHealth()
	e.decide()
	if err := e.Apply("startup"); err != nil {
		logx.Warnf("startup apply had errors (continuing)")
	}
	go e.refreshASNs(false)
	go e.PreResolve()

	cfg := e.runtime()
	healthT := time.NewTicker(time.Duration(cfg.Settings.HealthInterval) * time.Second)
	hookT := time.NewTicker(30 * time.Second)
	asnT := time.NewTicker(time.Hour)
	saveT := time.NewTicker(time.Duration(cfg.Settings.SaveInterval) * time.Second)
	sessT := time.NewTicker(20 * time.Second) // renew live sessions, end expired ones
	defer sessT.Stop()
	defer healthT.Stop()
	defer hookT.Stop()
	defer asnT.Stop()
	defer saveT.Stop()

	e.checkHealth(true)
	for {
		select {
		case <-ctx.Done():
			e.saveSets()
			e.stopSNI()
			e.rtc.Stop()
			e.dns.Stop()
			e.fwd.Stop()
			logx.Infof("daemon stopped")
			return nil
		case <-healthT.C:
			e.checkHealth(false)
		case <-e.kick:
			e.checkHealth(true)
		case <-hookT.C:
			e.mu.Lock()
			hooks := e.plan.Hooks
			e.mu.Unlock()
			if len(hooks) > 0 && !(netfilter.Applier{R: e.R}).HooksPresent(hooks) {
				logx.Warnf("firewall hooks missing (firewall restarted?), re-applying")
				_ = e.Apply("firewall restart detected")
			}
		case <-asnT.C:
			go e.refreshASNs(false)
		case <-saveT.C:
			e.saveSets()
		case <-sessT.C:
			if !e.Disabled() {
				e.refreshSessionsNow()
			}
		}
	}
}

// checkHealth probes all used tunnels in parallel, runs failover and applies
// when needed.
func (e *Engine) checkHealth(geo bool) {
	cfg := e.runtime()
	if !e.DryRun && !e.Disabled() {
		e.restartOpenVPN(cfg) // clients that exited (server down, network change)
	}
	tunnels := usedTunnels(cfg)
	e.mon.Prune(tunnels)
	var wg sync.WaitGroup
	for _, t := range tunnels {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			e.mon.Check(cfg.Settings, t, geo)
		}(t)
	}
	wg.Wait()

	snap := e.mon.Snapshot()
	var lk []string
	for _, t := range tunnels {
		s := snap[t]
		lk = append(lk, fmt.Sprintf("%s:%v%v%v", t, s.Exists, s.Up, s.HasIPv6))
	}
	// A reconnect can give the tunnel a new address: the rules that keep
	// its connections in it name the address.
	addrs := tunnelAddrs(tunnels)
	for _, t := range tunnels { // fixed order: the key must be stable
		ifc := config.TunnelInterface(t)
		lk = append(lk, ifc+"="+strings.Join(addrs[ifc], "/"))
	}
	// Refresh WAN-affinity guards after a DHCP/PPPoE address change too.
	lk = append(lk, "wan="+strings.Join(e.wanAddrs(), "/"))
	linkKey := strings.Join(lk, ",")
	e.mu.Lock()
	linkChanged := linkKey != e.linkKey
	e.linkKey = linkKey
	e.mu.Unlock()

	changed := e.decide()
	if len(changed) > 0 || linkChanged {
		reason := "tunnel state change"
		if len(changed) > 0 {
			reason = "failover"
		}
		_ = e.Apply(reason)
		for _, id := range changed {
			e.flushConntrack(id)
		}
	}
}

func (e *Engine) saveSets() {
	if e.DryRun {
		return
	}
	if e.Disabled() {
		// The sets are gone; saving now would wipe what Enable restores.
		e.saveLearnings()
		e.saveDNSRecords()
		return
	}
	ips := e.ipset()
	var names []string
	for _, n := range ips.Names() {
		// Only DNS-learned sets are worth persisting; static sets are
		// rebuilt and server sets come from the learning store.
		if strings.HasSuffix(n, "_"+netfilter.KindDomain+"4") || strings.HasSuffix(n, "_"+netfilter.KindDomain+"6") {
			names = append(names, n)
		}
	}
	if err := ips.Save(e.P.IPSetSave, names); err != nil {
		logx.Warnf("save ipsets: %v", err)
	}
	e.saveLearnings()
	e.saveDNSRecords()
}

// PolicyStatus is the runtime view of a policy.
type PolicyStatus struct {
	ID          int            `json:"id"`
	Name        string         `json:"name"`
	Enabled     bool           `json:"enabled"`
	Scope       string         `json:"scope"`
	Active      string         `json:"active"`
	KillEngaged bool           `json:"kill_engaged"`
	Leaking     bool           `json:"leaking"` // no tunnel and no kill switch: traffic uses WAN
	IPv6Mode    string         `json:"ipv6_mode"`
	WebRTCMode  string         `json:"webrtc_mode"`
	Candidates  []Candidate    `json:"candidates"`
	Sets        map[string]int `json:"sets"`
	Packets     uint64         `json:"packets"`
	Bytes       uint64         `json:"bytes"`
	WebRTC      *webrtc.Stats  `json:"webrtc,omitempty"`
	ASNErrors   []string       `json:"asn_errors,omitempty"`
	DomainMode  string         `json:"domain_mode,omitempty"`
	DNSUpstream *dnsfwd.Stats  `json:"dns_upstream,omitempty"` // DoT/DoH forwarder
	SNIMatched  *uint64        `json:"sni_matched,omitempty"`  // connections routed by server name (sniff_sni)
	Sessions    int            `json:"sessions,omitempty"`     // active device sessions (session: rules, WebRTC peers)
	Country     string         `json:"country,omitempty"`
}

// Status is the API status document.
type Status struct {
	Version    string                   `json:"version"`
	Disabled   bool                     `json:"disabled"`
	DisabledAt *time.Time               `json:"disabled_at,omitempty"`
	Uptime     string                   `json:"uptime"`
	Caps       Caps                     `json:"caps"`
	LastApply  time.Time                `json:"last_apply"`
	ApplyCount int                      `json:"apply_count"`
	LastError  string                   `json:"last_error,omitempty"`
	WANIP      string                   `json:"wan_ip"`
	Tunnels    map[string]health.Status `json:"tunnels"`
	Policies   []PolicyStatus           `json:"policies"`
	Events     []Event                  `json:"events"`
	DNS        *dnsinspect.Stats        `json:"dns_inspector,omitempty"`
	SNI        *sniproxy.Stats          `json:"sni_proxy,omitempty"`
	Warnings   []string                 `json:"warnings,omitempty"`
}

// Status builds the status document.
func (e *Engine) Status() Status {
	cfg := e.runtime()
	e.mu.Lock()
	caps := e.caps
	st := Status{
		Version:    Version,
		Disabled:   e.disabled.Load(),
		Uptime:     time.Since(e.started).Round(time.Second).String(),
		Caps:       caps,
		LastApply:  e.lastApply,
		ApplyCount: e.applyCount,
		LastError:  e.lastError,
		Events:     append([]Event(nil), e.events...),
	}
	active := map[int]string{}
	for k, v := range e.active {
		active[k] = v
	}
	cands := map[int][]Candidate{}
	for k, v := range e.cands {
		cands[k] = v
	}
	asnErr := map[int]string{}
	for k, v := range e.asnErrors {
		asnErr[k] = v
	}
	dnsOn := e.dnsOn
	sniErr := e.sniErr
	e.mu.Unlock()
	st.Warnings = e.Warnings()
	var sniStats sniproxy.Stats
	if e.sni.Running() || sniErr != "" {
		sniStats = e.sni.Stats()
		if sniErr != "" {
			sniStats.LastError = sniErr
		}
		st.SNI = &sniStats
	}
	if st.Disabled {
		if t := e.DisabledSince(); !t.IsZero() {
			st.DisabledAt = &t
		}
	}
	if dnsOn {
		ds := e.dns.Stats()
		st.DNS = &ds
	}
	st.WANIP = system.NVRAM{R: e.R}.Get("wan0_ipaddr")
	st.Tunnels = e.mon.Snapshot()
	ips := e.ipset()
	counters := (netfilter.Applier{R: e.R}).Counters(false)
	if caps.IPv6 {
		for k, v := range (netfilter.Applier{R: e.R}).Counters(true) {
			c := counters[k]
			counters[k] = [2]uint64{c[0] + v[0], c[1] + v[1]}
		}
	}
	rtcStats := e.rtc.Stats()
	fwdStats := e.fwd.Stats()
	states := e.states(cfg, caps)
	stByID := map[int]netfilter.PolicyState{}
	for _, s := range states {
		stByID[s.Policy.ID] = s
	}
	for _, p := range cfg.Policies {
		ps := PolicyStatus{ID: p.ID, Name: p.Name, Enabled: p.Enabled, Scope: p.Scope(), Sets: map[string]int{}}
		if p.Enabled {
			ps.Active = active[p.ID]
			ps.KillEngaged = ps.Active == "" && p.KillSwitch
			ps.Leaking = ps.Active == "" && !p.KillSwitch
			ps.Candidates = cands[p.ID]
			s := stByID[p.ID]
			ps.IPv6Mode, ps.WebRTCMode = s.IPv6Mode, s.WebRTCMode
			for _, kind := range []string{netfilter.KindDomain, netfilter.KindNet, netfilter.KindSession, netfilter.KindServer, netfilter.KindDrop, netfilter.KindDropNet} {
				for _, v6 := range []bool{false, true} {
					if v6 && !caps.IPv6 {
						continue
					}
					n := netfilter.SetName(p.ID, kind, v6)
					if c := ips.Count(n); c >= 0 {
						ps.Sets[n] = c
					}
				}
			}
			c := counters[netfilter.MarkChain(p.ID)]
			ps.Packets, ps.Bytes = c[0], c[1]
			if rs, ok := rtcStats[p.ID]; ok {
				rs := rs
				ps.WebRTC = &rs
			}
			for _, n := range p.ASNs {
				if msg, ok := asnErr[n]; ok {
					ps.ASNErrors = append(ps.ASNErrors, msg)
				}
			}
			if ps.Active != "" {
				ps.Country = st.Tunnels[ps.Active].Country
			}
			ps.Sessions = len(e.Sessions(p.ID))
			if p.Sniffs() && st.SNI != nil {
				n := sniStats.ByPolicy[p.ID]
				ps.SNIMatched = &n
			}
			if fs, ok := fwdStats[p.ID]; ok {
				fs := fs
				ps.DNSUpstream = &fs
			}
			if p.HasDomains() {
				rules := p.DomainRules()
				switch {
				case dnsOn && rules.NeedsInspector():
					ps.DomainMode = "inspector"
				case dnsOn:
					ps.DomainMode = "dnsmasq + inspector (CNAME)"
				case rules.NeedsInspector():
					ps.DomainMode = "degraded: plain rules only"
				default:
					ps.DomainMode = "dnsmasq"
				}
			}
		}
		st.Policies = append(st.Policies, ps)
	}
	return st
}

// DomainTest is the result of the "test domain" tool.
type DomainTest struct {
	Domain   string           `json:"domain"`
	Chain    []string         `json:"chain,omitempty"` // CNAME chain
	Policy   string           `json:"policy,omitempty"`
	PolicyID int              `json:"policy_id,omitempty"`
	Matched  string           `json:"matched,omitempty"`     // rule that matched
	Blocked  bool             `json:"blocked,omitempty"`     // a drop: rule matched, or an address is in a drop set
	Via      string           `json:"matched_via,omitempty"` // name in the chain that matched
	Excluded []string         `json:"excluded,omitempty"`    // policies vetoed by an exclusion
	Tunnel   string           `json:"tunnel,omitempty"`
	Country  string           `json:"country,omitempty"`
	Addrs    []AddrResult     `json:"addrs"`
	Error    string           `json:"error,omitempty"`
	Notes    []string         `json:"notes,omitempty"`
	Others   []map[string]any `json:"other_matches,omitempty"`
}

// AddrResult tells whether a resolved address is in the policy sets.
type AddrResult struct {
	IP      string `json:"ip"`
	InSet   string `json:"in_set,omitempty"`
	Blocked string `json:"blocked_by,omitempty"` // drop set holding the address
}

// MatchDomain finds the first enabled policy whose rules match name or (with
// CNAME following) any name of its chain.
func MatchDomain(cfg *config.Config, name string, chain ...string) (config.Policy, match.Result, []string, bool) {
	return matchDomain(cfg, config.Policy.DomainRules, name, chain...)
}

func matchDomain(cfg *config.Config, rules func(config.Policy) *match.Set, name string, chain ...string) (config.Policy, match.Result, []string, bool) {
	names := append([]string{match.Normalize(name)}, chain...)
	var excluded []string
	for _, p := range cfg.Policies {
		if !p.Enabled || (!p.HasDomains() && !p.HasDrops()) {
			continue
		}
		ns := names
		if p.IgnoreCNAME {
			ns = names[:1]
		}
		res := rules(p).MatchAny(ns...)
		if res.Matched {
			return p, res, excluded, true
		}
		if res.Excluded != "" {
			excluded = append(excluded, p.Name+" ("+res.Excluded+")")
		}
	}
	return config.Policy{}, match.Result{}, excluded, false
}

// TestDomain resolves a domain through dnsmasq (which also fills the sets)
// and reports how its traffic would be routed.
func (e *Engine) TestDomain(name string) DomainTest {
	cfg := e.runtime()
	name = match.Normalize(name)
	res := DomainTest{Domain: name}
	ans, err := dnsinspect.Query("127.0.0.1:53", name, 4*time.Second)
	if err != nil {
		res.Error = err.Error()
	}
	res.Chain = ans.Chain
	p, mr, excl, ok := matchDomain(cfg, e.domainSet, name, ans.Chain...)
	res.Excluded = excl
	ips := e.ipset()
	for _, ip := range ans.IPs {
		ar := AddrResult{IP: ip.String()}
		v6 := ip.To4() == nil
		for _, pol := range cfg.Policies {
			if !pol.Enabled {
				continue
			}
			if pol.HasDrops() {
				for _, k := range []string{netfilter.KindDrop, netfilter.KindDropNet} {
					if n := netfilter.SetName(pol.ID, k, v6); ar.Blocked == "" && ips.Test(n, ar.IP) {
						ar.Blocked = n
						res.Blocked = true
					}
				}
			}
			for _, k := range []string{netfilter.KindDomain, netfilter.KindNet} {
				n := netfilter.SetName(pol.ID, k, v6)
				if ips.Test(n, ar.IP) {
					if ar.InSet == "" {
						ar.InSet = n
					}
					if !ok && k == netfilter.KindNet {
						res.Others = append(res.Others, map[string]any{"policy": pol.Name, "set": n, "ip": ar.IP})
					}
				}
			}
		}
		res.Addrs = append(res.Addrs, ar)
	}
	if ok && mr.Drop {
		res.Policy, res.PolicyID, res.Matched, res.Via, res.Blocked = p.Name, p.ID, mr.Rule, mr.Name, true
		res.Notes = append(res.Notes, "blocked by a drop: rule: connections to these addresses are rejected for the policy's devices")
		for _, a := range res.Addrs {
			if a.Blocked == "" {
				res.Notes = append(res.Notes, a.IP+" is not in the drop set yet: is the router's dnsmasq the resolver? (check DNS hijack / DoH blocking)")
			}
		}
		return res
	}
	for _, a := range res.Addrs {
		if a.Blocked != "" {
			res.Notes = append(res.Notes, a.IP+" is in "+a.Blocked+": connections to it are rejected (drop rule)")
		}
	}
	if ok {
		res.Policy, res.PolicyID, res.Matched, res.Via = p.Name, p.ID, mr.Rule, mr.Name
		e.mu.Lock()
		res.Tunnel = e.active[p.ID]
		dnsOn := e.dnsOn
		e.mu.Unlock()
		if res.Tunnel != "" {
			if st, ok := e.mon.Get(res.Tunnel); ok {
				res.Country = st.Country
			}
		} else if p.KillSwitch {
			res.Notes = append(res.Notes, "no healthy tunnel: kill switch is blocking this traffic")
		} else {
			res.Notes = append(res.Notes, "no healthy tunnel: traffic currently goes via WAN")
		}
		if !dnsOn && (mr.Name != name || e.domainSet(p).NeedsInspector()) {
			res.Notes = append(res.Notes, "this match needs the DNS inspector, which is not running (kernel without NFQUEUE?)")
		}
		if mr.Route {
			steps := e.domainSet(p).StepsFor(mr.Name, name)
			if len(steps) > 1 {
				res.Notes = append(res.Notes, fmt.Sprintf("%d route/drop rules match: a device's lookup applies them top to bottom, so for an address the last one wins", len(steps)))
			}
			for _, st := range steps {
				res.Notes = append(res.Notes, stepNotes(st, e.sessionTTL(), mr.Name, name)...)
			}
		}
		if len(mr.Cond) > 0 {
			res.Notes = append(res.Notes, "matches the if: part of a conditional rule: routed for every device, and connections to these addresses make that rule's condition hold for the device")
		}
		if mr.Session || mr.Route {
			ttl := e.sessionTTL()
			if mr.Opts.TTL > 0 {
				ttl = mr.Opts.TTL
			}
			if len(mr.Opts.Share) > 0 {
				res.Notes = append(res.Notes, "sessions are shared with: "+strings.Join(mr.Opts.Share, ", "))
			}
			if mr.Opts.OnLookup {
				res.Notes = append(res.Notes, fmt.Sprintf("sessions last %s from the lookup (onlookup=1)", ttl))
			}
			if mr.Session {
				res.Notes = append(res.Notes, fmt.Sprintf("session: rule: these addresses are routed only for the device that looked the name up, until %s after its last connection to them; they are not added to the policy's sets", ttl))
			}
			if n := len(e.Sessions(p.ID)); n > 0 {
				res.Notes = append(res.Notes, fmt.Sprintf("the policy has %d active session(s) (Learnings → Policy addresses, kind session)", n))
			}
		} else {
			for _, a := range res.Addrs {
				if a.InSet == "" {
					res.Notes = append(res.Notes, a.IP+" is not in any set yet: is the router's dnsmasq the resolver? (check DNS hijack / DoH blocking)")
				}
			}
		}
		if len(p.Devices) > 0 {
			res.Notes = append(res.Notes, "policy is limited to selected devices")
		}
		if n := len(p.ExcludeDevices); n > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%d excluded device(s) or group(s) are never routed by this policy", n))
		}
	} else if len(res.Others) == 0 {
		res.Notes = append(res.Notes, "no policy matches: traffic goes via WAN")
	}
	return res
}

// SetMembers lists members of a snake set.
func (e *Engine) SetMembers(name string, limit int) ([]string, error) {
	if !strings.HasPrefix(name, netfilter.SetPrefix) {
		return nil, fmt.Errorf("not a snake set")
	}
	return e.ipset().Members(name, limit), nil
}

// FlushLearned empties DNS-learned and WebRTC sets of a policy. Learning
// groups are managed separately (Learnings tab).
func (e *Engine) FlushLearned(id int) {
	ips := e.ipset()
	e.clearSessions(id)
	for _, k := range []string{netfilter.KindDomain, netfilter.KindDrop, netfilter.KindSession} {
		for _, v6 := range []bool{false, true} {
			_ = ips.Flush(netfilter.SetName(id, k, v6))
		}
	}
	e.event("", "flush", "flushed learned addresses of policy %d", id)
	go e.PreResolve()
}

// Client is a LAN client seen by the router.
type Client struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

// Clients merges dnsmasq leases and the ARP table.
func Clients() []Client {
	byMAC := map[string]*Client{}
	if f, err := os.Open("/var/lib/misc/dnsmasq.leases"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			x := strings.Fields(sc.Text())
			if len(x) >= 4 {
				if m, err := config.NormalizeMAC(x[1]); err == nil {
					name := x[3]
					if name == "*" {
						name = ""
					}
					byMAC[m] = &Client{MAC: m, IP: x[2], Name: name}
				}
			}
		}
		f.Close()
	}
	if f, err := os.Open("/proc/net/arp"); err == nil {
		sc := bufio.NewScanner(f)
		sc.Scan()
		for sc.Scan() {
			x := strings.Fields(sc.Text())
			if len(x) >= 6 && strings.HasPrefix(x[5], "br") {
				m, err := config.NormalizeMAC(x[3])
				if err != nil || m == "00:00:00:00:00:00" {
					continue
				}
				if _, ok := byMAC[m]; !ok {
					byMAC[m] = &Client{MAC: m, IP: x[0]}
				}
			}
		}
		f.Close()
	}
	out := make([]Client, 0, len(byMAC))
	for _, c := range byMAC {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := net.ParseIP(out[i].IP), net.ParseIP(out[j].IP)
		if a != nil && b != nil {
			return strings.Compare(string(a.To16()), string(b.To16())) < 0
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// LeakCheck is a router-side audit of leak protections.
type LeakCheck struct {
	Policy string   `json:"policy"`
	OK     []string `json:"ok"`
	Warn   []string `json:"warn"`
}

// LeakChecks audits each policy's protections against the live state.
func (e *Engine) LeakChecks() []LeakCheck {
	cfg := e.runtime()
	st := e.Status()
	byID := map[int]PolicyStatus{}
	for _, p := range st.Policies {
		byID[p.ID] = p
	}
	var out []LeakCheck
	for _, p := range cfg.Policies {
		if !p.Enabled {
			continue
		}
		ps := byID[p.ID]
		lc := LeakCheck{Policy: p.Name}
		ok := func(f string, a ...any) { lc.OK = append(lc.OK, fmt.Sprintf(f, a...)) }
		warn := func(f string, a ...any) { lc.Warn = append(lc.Warn, fmt.Sprintf(f, a...)) }
		switch {
		case ps.Active != "":
			ok("routed via %s", ps.Active)
		case ps.KillEngaged:
			warn("no healthy tunnel: kill switch engaged (traffic blocked)")
		default:
			warn("no healthy tunnel and kill switch off: traffic is using WAN")
		}
		if p.ExpectedCountry != "" && ps.Active != "" {
			if ps.Country == p.ExpectedCountry {
				ok("exit country %s matches", ps.Country)
			} else if ps.Country == "" {
				warn("exit country unknown (geo lookup failed)")
			}
		}
		if p.HasDomains() {
			if p.Leak.HijackDNS {
				ok("hardcoded DNS (port 53) redirected to router")
			} else {
				warn("DNS hijack off: devices with hardcoded DNS bypass the domain sets")
			}
			s := cfg.Settings
			override := func(mode string) string {
				switch mode {
				case config.BlockAlways:
					return " (Settings: always, whole LAN)"
				case config.BlockNever:
					return " (Settings: never)"
				}
				return ""
			}
			sniffing := p.Sniffs() && st.SNI != nil && st.SNI.Listen != ""
			if p.Sniffs() {
				switch {
				case sniffing:
					ech := "Encrypted Client Hello connections are routed by their public name"
					switch p.Leak.ECH {
					case config.ECHDrop:
						ech = "Encrypted Client Hello connections are refused"
					case config.ECHPassthrough:
						ech = "Encrypted Client Hello connections are passed through via WAN, untouched by this policy (its drop: rules do not apply to them)"
					}
					ok("HTTPS the domain sets miss is routed by TLS server name (SNI proxy %s); unclaimed QUIC is rejected so it falls back to TCP; %s", st.SNI.Listen, ech)
					if st.Caps.IPv6 && !st.Caps.IPv6NAT {
						warn("IPv6 HTTPS is not sniffed (no ip6tables NAT): devices using encrypted DNS over IPv6 bypass the domain rules")
					}
				case st.SNI != nil && st.SNI.LastError != "":
					warn("SNI sniffing on but the proxy is not running: %s", st.SNI.LastError)
				default:
					warn("SNI sniffing on but the proxy is not running")
				}
			}
			if s.DoHBlocked(p) {
				ok("known DoH resolvers blocked%s", override(s.BlockDoH))
			} else if sniffing {
				ok("DoH allowed%s: lookups are hidden, connections are routed by SNI", override(s.BlockDoH))
			} else {
				warn("DoH not blocked%s: browsers/apps with DoH bypass the domain sets", override(s.BlockDoH))
			}
			if s.DoTBlocked(p) {
				ok("DoT/DoQ (853) blocked%s", override(s.BlockDoT))
			} else if sniffing {
				ok("DoT allowed%s: lookups are hidden, connections are routed by SNI", override(s.BlockDoT))
			} else {
				warn("DoT not blocked%s (Android Private DNS bypasses the domain sets)", override(s.BlockDoT))
			}
			if p.Leak.DNSViaTunnel {
				via := "plain DNS"
				switch p.Leak.DNSProtocol {
				case config.DNSDoT:
					via = "DNS over TLS (" + p.Leak.DNSTLSName + ")"
				case config.DNSDoH:
					via = "DNS over HTTPS (" + p.Leak.DNSTLSName + ")"
				}
				ok("policy domains resolved by %s with %s through the tunnel (CDN picks servers near the exit)", p.Leak.DNSServer, via)
				if u := ps.DNSUpstream; u != nil && u.LastError != "" && time.Since(u.LastErrAt) < 10*time.Minute {
					warn("%s lookups failing (%d of %d): %s", via, u.Errors, u.Queries, u.LastError)
				}
			} else {
				warn("policy domains resolved via WAN DNS: CDNs may pick servers near your real location")
			}
		}
		switch ps.IPv6Mode {
		case netfilter.V6Route:
			ok("IPv6 routed through tunnel")
		case netfilter.V6Block:
			ok("IPv6 blocked for policy traffic")
		default:
			if st.Caps.IPv6 {
				warn("IPv6 protection off: IPv6 traffic may leak")
			} else {
				ok("router has no IPv6")
			}
		}
		switch ps.WebRTCMode {
		case netfilter.RTCQueue:
			ok("WebRTC tracked (STUN learning via NFQUEUE; servers of learning groups routed via this policy are covered before a session starts)")
		case netfilter.RTCPorts:
			warn("WebRTC tracked in fallback mode (NFQUEUE unavailable: only STUN/TURN ports during sessions)")
		default:
			if p.Scope() == "whole-device" {
				ok("whole device routed: WebRTC included")
			} else {
				warn("WebRTC tracking off: peer-to-peer media of this service uses WAN")
			}
		}
		if p.HasDomains() {
			rules := p.DomainRules()
			if rules.NeedsInspector() && !st.Caps.NFQueue {
				warn("wildcard/regex/keyword rules and exclusions need NFQUEUE, which this kernel lacks: only plain domain rules are active")
			} else if st.Caps.NFQueue {
				ok("domain rules matched by DNS inspection (wildcards, regexes, CNAME chains)")
			}
		}
		if ps.Sets[netfilter.SetName(p.ID, netfilter.KindDomain, false)] == 0 && p.HasDomains() && !p.Sniffs() {
			warn("domain set empty: no client has resolved these domains through the router yet")
		}
		out = append(out, lc)
	}
	return out
}

// stepNotes explains what a route/drop session rule does with a name.
func stepNotes(st match.Step, defTTL time.Duration, names ...string) []string {
	what := func(kind string, o match.Opts) string {
		verb := "routed through the tunnel"
		if kind == match.ActDrop {
			verb = "blocked"
		}
		if o.Permanent() {
			switch o.SetMode() {
			case match.SetOff:
				return "no longer " + verb + " for that device (set=0 ends its " + kind + " session)"
			case match.SetToggle:
				return verb + " for that device if they were not, and no longer if they were (set=toggle; until the next toggle)"
			}
			s := verb + " for that device until a set=0 or set=toggle lookup (a permanent " + kind + " session"
			if len(o.Share) > 0 {
				s += "; shared with " + strings.Join(o.Share, ", ")
			}
			return s + ")"
		}
		ttl := defTTL
		if o.TTL > 0 {
			ttl = o.TTL
		}
		s := fmt.Sprintf("%s for that device (a %s session, %s", verb, kind, match.FormatTTL(ttl))
		if o.OnLookup {
			s += " from the lookup"
		} else {
			s += " after its last connection"
		}
		if len(o.Share) > 0 {
			s += "; shared with " + strings.Join(o.Share, ", ")
		}
		return s + ")"
	}
	act := func(a *match.Action) string {
		if a == nil {
			return "nothing (not handled by this rule)"
		}
		return what(a.Kind, a.Opts)
	}
	if st.Drop != nil {
		return []string{"drop[...] rule " + st.Raw() + ": a device's lookup of this name makes its addresses " + what(match.ActDrop, st.Drop.Opts) + "; other devices are not affected"}
	}
	rt := st.Route
	if rt.If == nil {
		return []string{"route: rule: a device's lookup of this name makes its addresses " + act(rt.Pick(true, names...)) + "; they are not added to the policy's sets"}
	}
	return []string{
		"conditional rule: when a device has a live connection to an address of the if: names, its lookup of this name makes the addresses " + act(rt.Pick(true, names...)),
		"otherwise: " + act(rt.Pick(false, names...)) + "; the addresses are not added to the policy's sets",
	}
}
