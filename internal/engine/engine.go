// Package engine turns configuration plus tunnel health into kernel state and
// runs the daemon loop.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irisariuan/snake/internal/asn"
	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsinspect"
	"github.com/irisariuan/snake/internal/dnsmasq"
	"github.com/irisariuan/snake/internal/health"
	"github.com/irisariuan/snake/internal/learn"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/routing"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/webrtc"
)

// Version is set at build time.
var Version = "dev"

// Paths are the on-router file locations.
type Paths struct {
	Base      string
	Config    string
	DNSMasq   string
	IPSetSave string
	ASNDir    string
	Learnings string
	Socket    string
	PID       string
}

// DefaultPaths returns the standard /jffs layout.
func DefaultPaths(base string) Paths {
	return Paths{
		Base:      base,
		Config:    filepath.Join(base, "config.json"),
		DNSMasq:   filepath.Join(base, "dnsmasq.conf"),
		IPSetSave: filepath.Join(base, "ipsets.save"),
		ASNDir:    filepath.Join(base, "asn"),
		Learnings: filepath.Join(base, "learnings.json"),
		Socket:    "/var/run/snake.sock",
		PID:       "/var/run/snake.pid",
	}
}

// Caps are detected router capabilities.
type Caps struct {
	IPv6      bool `json:"ipv6"`
	IPv6NAT   bool `json:"ipv6_nat"`
	NFQueue   bool `json:"nfqueue"`
	Conntrack bool `json:"conntrack_tool"`
	Procfs    bool `json:"conntrack_procfs"`
	// IPSetNetlink: set entries are added and tested over netlink instead
	// of by running the ipset tool.
	IPSetNetlink bool `json:"ipset_netlink"`
}

// Event is a notable state change.
type Event struct {
	Time   time.Time `json:"time"`
	Policy string    `json:"policy,omitempty"`
	Kind   string    `json:"kind"`
	Msg    string    `json:"msg"`
}

// Engine owns the running state.
type Engine struct {
	P      Paths
	R      system.Runner
	DryRun bool

	mu          sync.Mutex
	applyMu     sync.Mutex     // serialises kernel updates
	cfgMu       sync.Mutex     // serialises read-modify-write config updates
	cfg         *config.Config // as stored (rule lists referenced by name)
	rt          *config.Config // runtime copy: rule lists merged into policies
	caps        Caps
	mon         *health.Monitor
	rtc         *webrtc.Tracker
	nl          *netfilter.NL
	compiled    map[int]*match.Set // domain rules of compiledFor, by policy id
	compiledFor *config.Config
	learn       *learn.Store
	learnMu     sync.Mutex   // serialises learning-set syncs
	learnRoute  atomic.Value // map[string]int: server -> policy (0 = WAN), as installed
	dns         *dnsinspect.Inspector
	dnsOn       bool
	asnCache    *asn.Cache
	active      map[int]string
	cands       map[int][]Candidate
	events      []Event
	plan        netfilter.Plan
	lastApply   time.Time
	lastError   string
	asnErrors   map[int]string
	netHashes   map[string]string
	rtcKey      string
	started     time.Time
	applyCount  int
	linkKey     string
	kick        chan struct{}
	daemon      bool
}

// New creates an engine.
func New(p Paths, r system.Runner) *Engine {
	e := &Engine{
		P:         p,
		R:         r,
		mon:       health.NewMonitor(r),
		rtc:       webrtc.NewTracker(netfilter.IPSet{R: r}, 0),
		dns:       &dnsinspect.Inspector{IPSet: netfilter.IPSet{R: r}},
		active:    map[int]string{},
		cands:     map[int][]Candidate{},
		asnErrors: map[int]string{},
		netHashes: map[string]string{},
		started:   time.Now(),
		kick:      make(chan struct{}, 1),
	}
	e.rtc.ServerRoute = e.serverRoute
	e.rtc.OnServer = e.onServer
	e.rtc.OnScan = e.onScan
	return e
}

// Load reads configuration from disk.
func (e *Engine) Load() error {
	c, err := config.Load(e.P.Config)
	if err != nil {
		return err
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	e.mu.Lock()
	e.cfg, e.rt = c, c.Runtime()
	e.rtc.MarkMask = c.Settings.MarkMask
	e.asnCache = &asn.Cache{Dir: e.P.ASNDir, MaxAge: time.Duration(c.Settings.ASNRefresh) * time.Hour}
	e.mu.Unlock()
	return e.openLearnings()
}

// Config returns a deep copy of the current configuration.
func (e *Engine) Config() *config.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return cloneConfig(e.cfg)
}

func cloneConfig(c *config.Config) *config.Config {
	if c == nil {
		return config.Default()
	}
	// Round-trip through JSON: a true deep copy that keeps empty lists as []
	// (not null) for API clients.
	b, err := json.Marshal(c)
	if err != nil {
		return config.Default()
	}
	var cp config.Config
	if err := json.Unmarshal(b, &cp); err != nil {
		return config.Default()
	}
	return &cp
}

// SetConfig validates, persists and applies a new configuration.
func (e *Engine) SetConfig(c *config.Config) error {
	c.ApplyDefaults()
	c.Normalize()
	if err := c.Validate(); err != nil {
		return err
	}
	if !e.DryRun {
		if err := config.Save(e.P.Config, c); err != nil {
			return err
		}
	}
	e.mu.Lock()
	e.cfg, e.rt = c, c.Runtime()
	e.rtc.MarkMask = c.Settings.MarkMask
	e.asnCache = &asn.Cache{Dir: e.P.ASNDir, MaxAge: time.Duration(c.Settings.ASNRefresh) * time.Hour}
	e.mu.Unlock()
	e.event("", "config", "configuration saved")
	err := e.Apply("config change")
	go e.refreshASNs(false)
	go e.PreResolve()
	return err
}

// DetectCaps probes router capabilities.
func (e *Engine) DetectCaps() {
	nv := system.NVRAM{R: e.R}
	c := Caps{}
	svc := nv.Get("ipv6_service")
	_, kerr := os.Stat("/proc/net/if_inet6")
	c.IPv6 = svc != "" && svc != "disabled" && system.Exists("ip6tables-restore") && kerr == nil
	if c.IPv6 {
		_, err := e.R.Run("ip6tables", "-t", "nat", "-S", "POSTROUTING")
		c.IPv6NAT = err == nil
	}
	c.NFQueue = webrtc.Supported(e.R)
	c.Conntrack = system.Exists("conntrack")
	_, err := os.Stat("/proc/net/nf_conntrack")
	c.Procfs = err == nil
	if !e.DryRun {
		e.mu.Lock()
		have := e.nl != nil
		e.mu.Unlock()
		if !have {
			if nl, err := netfilter.OpenNL(); err == nil {
				e.mu.Lock()
				e.nl = nl
				e.mu.Unlock()
				e.dns.IPSet.NL = nl
				e.rtc.IPSet.NL = nl
			} else {
				logx.Infof("ipset over netlink unavailable, using the ipset tool: %v", err)
			}
		}
		c.IPSetNetlink = e.ipset().NL.Usable()
	}
	e.mu.Lock()
	e.caps = c
	e.mu.Unlock()
	logx.Infof("capabilities: ipv6=%v ipv6nat=%v nfqueue=%v conntrack=%v ipset-netlink=%v", c.IPv6, c.IPv6NAT, c.NFQueue, c.Conntrack, c.IPSetNetlink)
}

func (e *Engine) event(policy, kind, format string, a ...any) {
	ev := Event{Time: time.Now(), Policy: policy, Kind: kind, Msg: fmt.Sprintf(format, a...)}
	logx.Infof("[%s] %s %s", kind, policy, ev.Msg)
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.events) >= 200 {
		e.events = e.events[1:]
	}
	e.events = append(e.events, ev)
}

// ipset returns the set manager, with netlink when available.
func (e *Engine) ipset() netfilter.IPSet {
	e.mu.Lock()
	defer e.mu.Unlock()
	return netfilter.IPSet{R: e.R, NL: e.nl}
}

// usedTunnels lists tunnels referenced by enabled policies.
func usedTunnels(c *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range c.Policies {
		if !p.Enabled {
			continue
		}
		for _, t := range p.Tunnels {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// decide runs failover for every policy; returns the ids whose active tunnel changed.
func (e *Engine) decide() []int {
	e.mu.Lock()
	cfg := e.rt
	e.mu.Unlock()
	snap := e.mon.Snapshot()
	now := time.Now()
	var changed []int
	type change struct{ name, from, to string }
	var changes []change
	e.mu.Lock()
	ids := map[int]bool{}
	for _, p := range cfg.Policies {
		if !p.Enabled {
			continue
		}
		ids[p.ID] = true
		cur := e.active[p.ID]
		next, cands := Select(p, cur, snap, cfg.Settings, now)
		e.cands[p.ID] = cands
		if next != cur {
			e.active[p.ID] = next
			changed = append(changed, p.ID)
			changes = append(changes, change{p.Name, cur, next})
		}
	}
	for id := range e.active {
		if !ids[id] {
			delete(e.active, id)
			delete(e.cands, id)
		}
	}
	e.mu.Unlock()
	for _, c := range changes {
		switch {
		case c.to == "":
			e.event(c.name, "failover", "no usable tunnel (was %s)", orNone(c.from))
		case c.from == "":
			e.event(c.name, "failover", "active tunnel %s", c.to)
		default:
			e.event(c.name, "failover", "switched %s -> %s", c.from, c.to)
		}
	}
	return changed
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// states computes the runtime state for each enabled policy.
func (e *Engine) states(cfg *config.Config, caps Caps) []netfilter.PolicyState {
	snap := e.mon.Snapshot()
	var out []netfilter.PolicyState
	for _, p := range cfg.Policies {
		if !p.Enabled {
			continue
		}
		st := netfilter.PolicyState{Policy: p, MACs: cfg.ResolveDevices(p), ActiveTunnel: e.active[p.ID]}
		switch {
		case !caps.IPv6 || p.Leak.IPv6 == config.IPv6Off:
			st.IPv6Mode = netfilter.V6Off
		case p.Leak.IPv6 == config.IPv6Block:
			st.IPv6Mode = netfilter.V6Block
		case st.ActiveTunnel == "":
			if p.KillSwitch {
				st.IPv6Mode = netfilter.V6Block
			} else {
				st.IPv6Mode = netfilter.V6Off
			}
		case snap[st.ActiveTunnel].HasIPv6 && caps.IPv6NAT:
			st.IPv6Mode = netfilter.V6Route
		default:
			st.IPv6Mode = netfilter.V6Block
		}
		st.Drops = p.HasDrops()
		st.WebRTCMode = netfilter.RTCOff
		if p.Leak.WebRTC == config.WebRTCTrack && p.HasDestinations() {
			if caps.NFQueue {
				st.WebRTCMode = netfilter.RTCQueue
			} else {
				st.WebRTCMode = netfilter.RTCPorts
			}
		}
		out = append(out, st)
	}
	return out
}

func setSpecs(cfg *config.Config, states []netfilter.PolicyState, v6 bool) []netfilter.SetSpec {
	var specs []netfilter.SetSpec
	s := cfg.Settings
	anyDoH := false
	fams := []bool{false}
	if v6 {
		fams = append(fams, true)
	}
	for _, st := range states {
		p := st.Policy
		if p.Leak.BlockDoH {
			anyDoH = true
		}
		for _, f := range fams {
			if p.HasDomains() {
				specs = append(specs, netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindDomain, f), Type: "hash:net", V6: f, Timeout: s.DomainSetTimeout, MaxElem: 131072})
			}
			if len(p.ASNs)+len(p.CIDRs) > 0 {
				specs = append(specs, netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindNet, f), Type: "hash:net", V6: f, MaxElem: 262144})
			}
			if st.WebRTCMode != netfilter.RTCOff {
				specs = append(specs,
					netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindSession, f), Type: "hash:ip", V6: f, Timeout: s.SessionTimeout},
					netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindPeer, f), Type: "hash:ip", V6: f, Timeout: s.PeerTimeout, MaxElem: 65536},
				)
			}
			if st.Drops {
				specs = append(specs,
					netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindDrop, f), Type: "hash:net", V6: f, Timeout: s.DomainSetTimeout, MaxElem: 131072},
					netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindDropNet, f), Type: "hash:net", V6: f, MaxElem: 262144})
			}
			if st.WebRTCMode != netfilter.RTCOff {
				// Filled from the learning groups routed via this policy;
				// expiry is managed by the learning store, not the kernel.
				specs = append(specs, netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindServer, f), Type: "hash:ip", V6: f, MaxElem: 65536})
			}
		}
	}
	// DoH sets always exist (cheap) so dnsmasq never logs missing-set errors.
	_ = anyDoH
	specs = append(specs, netfilter.SetSpec{Name: netfilter.DoHSet4, Type: "hash:net"})
	if v6 {
		specs = append(specs, netfilter.SetSpec{Name: netfilter.DoHSet6, Type: "hash:net", V6: true})
	}
	return specs
}

// Apply pushes the full desired state into the kernel.
func (e *Engine) Apply(reason string) error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	cfg := e.rt
	caps := e.caps
	e.mu.Unlock()
	if cfg == nil {
		return fmt.Errorf("no configuration loaded")
	}
	s := cfg.Settings
	states := e.states(cfg, caps)
	ips := e.ipset()
	nf := netfilter.Applier{R: e.R}
	rt := routing.Manager{R: e.R}
	var errs []string

	// 1. ipsets
	specs := setSpecs(cfg, states, caps.IPv6)
	want := map[string]bool{}
	for _, sp := range specs {
		want[sp.Name] = true
		if err := ips.Ensure(sp); err != nil {
			errs = append(errs, err.Error())
		}
	}
	v4, v6 := netfilter.SplitFamilies(netfilter.DefaultDoHIPs)
	_, v6b := netfilter.SplitFamilies(netfilter.DefaultDoHIPv6)
	_ = ips.AddMany(netfilter.DoHSet4, v4)
	if caps.IPv6 {
		_ = ips.AddMany(netfilter.DoHSet6, append(v6, v6b...))
	}
	for _, st := range states {
		p := st.Policy
		if st.Drops {
			rs := e.domainSet(p)
			d4, d6 := netfilter.SplitFamilies(e.netEntriesOf(rs.DropASNs, rs.DropCIDRs))
			e.replaceIfChanged(ips, netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindDropNet, false), Type: "hash:net", MaxElem: 262144}, d4, &errs)
			if caps.IPv6 {
				e.replaceIfChanged(ips, netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindDropNet, true), Type: "hash:net", V6: true, MaxElem: 262144}, d6, &errs)
			}
		}
		if len(p.ASNs)+len(p.CIDRs) == 0 {
			continue
		}
		n4, n6 := netfilter.SplitFamilies(e.netEntries(p))
		e.replaceIfChanged(ips, netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindNet, false), Type: "hash:net", MaxElem: 262144}, n4, &errs)
		if caps.IPv6 {
			e.replaceIfChanged(ips, netfilter.SetSpec{Name: netfilter.SetName(p.ID, netfilter.KindNet, true), Type: "hash:net", V6: true, MaxElem: 262144}, n6, &errs)
		}
	}

	// 2. routing
	snap := e.mon.Snapshot()
	var routes []routing.PolicyRoute
	for _, st := range states {
		r := routing.PolicyRoute{
			ID:      st.Policy.ID,
			Iface:   "",
			Kill:    st.Policy.KillSwitch,
			V6:      st.IPv6Mode != netfilter.V6Off,
			V6Route: st.IPv6Mode == netfilter.V6Route,
		}
		if st.ActiveTunnel != "" {
			r.Iface = config.TunnelInterface(st.ActiveTunnel)
		}
		if st.Policy.Leak.DNSViaTunnel && st.Policy.HasDomains() {
			r.DNSServer = st.Policy.Leak.DNSServer
		}
		routes = append(routes, r)
	}
	var probes []routing.ProbeRoute
	for _, t := range usedTunnels(cfg) {
		ls := snap[t]
		probes = append(probes, routing.ProbeRoute{Tunnel: t, Iface: config.TunnelInterface(t), Up: ls.Exists && ls.Up})
		if ls.Exists && !e.DryRun {
			routing.LooseRPFilter(config.TunnelInterface(t))
		}
	}
	if err := rt.Sync(s, routes, probes, caps.IPv6); err != nil {
		errs = append(errs, err.Error())
	}

	// 3. netfilter
	existing := nf.ExistingChains(false)
	if caps.IPv6 {
		for k, v := range nf.ExistingChains(true) {
			existing[k] = v
		}
	}
	// DNS inspector: on whenever a policy has domain rules and the kernel
	// has NFQUEUE (needed for wildcards/regexes/exclusions and CNAME chains).
	dnsRules := e.dnsRules(states, caps)
	dnsOn := caps.NFQueue && len(dnsRules) > 0
	dnsQueue := 0
	if dnsOn {
		dnsQueue = s.QueueBase
	}
	plan := netfilter.Build(s, states, netfilter.Options{IPv6: caps.IPv6, IPv6NAT: caps.IPv6NAT, DNSQueue: dnsQueue, Existing: existing})
	if err := nf.Apply(plan); err != nil {
		errs = append(errs, err.Error())
	}

	// 4. stale sets (now unreferenced)
	for _, n := range ips.Names() {
		if !want[n] && !strings.HasSuffix(n, "_t") {
			_ = ips.Destroy(n)
		}
	}

	// 5. dnsmasq
	if !e.DryRun && e.isDaemon() {
		if dnsOn {
			ttl := 10 * time.Minute
			if s.DomainSetTimeout > 0 {
				ttl = time.Duration(s.DomainSetTimeout/2) * time.Second
			}
			e.dns.CacheTTL = ttl
			e.dns.SetRules(dnsRules)
			if err := e.dns.Start(uint16(s.QueueBase)); err != nil {
				errs = append(errs, err.Error())
			}
		} else {
			e.dns.Stop()
		}
	}
	e.mu.Lock()
	e.dnsOn = dnsOn
	e.mu.Unlock()

	frag := dnsmasq.Generate(cfg, dnsOn)
	if !e.DryRun {
		changed, err := system.WriteIfChanged(e.P.DNSMasq, []byte(frag), 0o644)
		if err != nil {
			errs = append(errs, err.Error())
		} else if changed {
			logx.Infof("dnsmasq fragment changed, restarting dnsmasq")
			if _, err := e.R.Run("service", "restart_dnsmasq"); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	// 6. WebRTC tracker
	var tracks []webrtc.PolicyTrack
	for _, st := range states {
		if st.WebRTCMode == netfilter.RTCOff {
			continue
		}
		tracks = append(tracks, webrtc.PolicyTrack{ID: st.Policy.ID, Queue: uint16(s.QueueBase + st.Policy.ID), Mark: s.PolicyMark(st.Policy.ID)})
	}
	key := fmt.Sprintf("%v%v%x", tracks, caps.NFQueue, s.MarkMask)
	e.mu.Lock()
	rtcChanged := key != e.rtcKey
	e.rtcKey = key
	e.mu.Unlock()
	if rtcChanged && !e.DryRun && e.isDaemon() {
		if err := e.rtc.Configure(tracks, caps.NFQueue); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// 7. learning groups -> per-policy server sets
	if err := e.syncLearnings(cfg); err != nil {
		errs = append(errs, err.Error())
	}

	e.mu.Lock()
	e.plan = plan
	e.lastApply = time.Now()
	e.applyCount++
	if len(errs) > 0 {
		e.lastError = strings.Join(errs, " | ")
	} else {
		e.lastError = ""
	}
	e.mu.Unlock()
	if len(errs) > 0 {
		logx.Errorf("apply (%s): %s", reason, strings.Join(errs, " | "))
		return fmt.Errorf("%s", strings.Join(errs, " | "))
	}
	logx.Infof("applied (%s): %d policies", reason, len(states))
	return nil
}

// dnsRules compiles the domain rules of enabled policies in policy order.
func (e *Engine) dnsRules(states []netfilter.PolicyState, caps Caps) []dnsinspect.Rules {
	var out []dnsinspect.Rules
	for _, st := range states {
		p := st.Policy
		if !p.HasDomains() && !st.Drops {
			continue
		}
		r := dnsinspect.Rules{ID: p.ID, Name: p.Name, Set: e.domainSet(p), FollowCNAME: !p.IgnoreCNAME}
		if p.HasDomains() {
			r.Set4 = netfilter.SetName(p.ID, netfilter.KindDomain, false)
			if caps.IPv6 {
				r.Set6 = netfilter.SetName(p.ID, netfilter.KindDomain, true)
			}
		}
		if st.Drops {
			r.DropSet4 = netfilter.SetName(p.ID, netfilter.KindDrop, false)
			if caps.IPv6 {
				r.DropSet6 = netfilter.SetName(p.ID, netfilter.KindDrop, true)
			}
		}
		out = append(out, r)
	}
	return out
}

func (e *Engine) isDaemon() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.daemon
}

func (e *Engine) replaceIfChanged(ips netfilter.IPSet, spec netfilter.SetSpec, entries []string, errs *[]string) {
	h := sha256.Sum256([]byte(strings.Join(entries, ",")))
	hs := fmt.Sprintf("%x", h[:8])
	e.mu.Lock()
	same := e.netHashes[spec.Name] == hs
	e.mu.Unlock()
	if same && ips.Count(spec.Name) == len(entries) {
		return
	}
	if err := ips.Replace(spec, entries); err != nil {
		*errs = append(*errs, err.Error())
		return
	}
	e.mu.Lock()
	e.netHashes[spec.Name] = hs
	e.mu.Unlock()
}

// netEntries returns static CIDRs plus cached ASN prefixes for a policy.
func (e *Engine) netEntries(p config.Policy) []string { return e.netEntriesOf(p.ASNs, p.CIDRs) }

// netEntriesOf returns CIDRs plus the cached prefixes of ASNs.
func (e *Engine) netEntriesOf(asns []int, cidrs []string) []string {
	out := append([]string(nil), cidrs...)
	e.mu.Lock()
	cache := e.asnCache
	e.mu.Unlock()
	for _, n := range asns {
		if cache == nil {
			break
		}
		// Cache only: network fetches happen in refreshASNs.
		pf, _ := (&asn.Cache{Dir: cache.Dir, MaxAge: 100 * 365 * 24 * time.Hour}).Prefixes(n, false)
		out = append(out, pf...)
	}
	return out
}

// refreshASNs fetches stale ASN prefix lists and re-applies if anything changed.
func (e *Engine) refreshASNs(force bool) {
	e.mu.Lock()
	cfg, cache := e.rt, e.asnCache
	e.mu.Unlock()
	if cfg == nil || cache == nil || e.DryRun {
		return
	}
	fetched := false
	for _, p := range cfg.Policies {
		if !p.Enabled {
			continue
		}
		asns := append(append([]int(nil), p.ASNs...), e.domainSet(p).DropASNs...)
		for _, n := range asns {
			if !force && !cache.Stale(n) {
				continue
			}
			_, err := cache.Prefixes(n, true)
			e.mu.Lock()
			if err != nil {
				e.asnErrors[n] = err.Error()
			} else {
				delete(e.asnErrors, n)
			}
			e.mu.Unlock()
			if err != nil {
				logx.Warnf("asn: %v", err)
			} else {
				fetched = true
			}
		}
	}
	if fetched {
		_ = e.Apply("ASN refresh")
	}
}

// PreResolve queries every policy domain through dnsmasq so the ipsets are
// warm before clients use cached answers.
func (e *Engine) PreResolve() {
	e.mu.Lock()
	cfg := e.rt
	e.mu.Unlock()
	if cfg == nil || !cfg.Settings.PreResolve || e.DryRun {
		return
	}
	r := LocalResolver()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, p := range cfg.Policies {
		if !p.Enabled {
			continue
		}
		for _, d := range p.DomainRules().Bases() {
			for _, h := range []string{d, "www." + d} {
				wg.Add(1)
				sem <- struct{}{}
				go func(h string) {
					defer wg.Done()
					defer func() { <-sem }()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_, _ = r.LookupIPAddr(ctx, h)
				}(h)
			}
		}
	}
	wg.Wait()
}

// LocalResolver queries the router's dnsmasq.
func LocalResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "127.0.0.1:53")
		},
	}
}

// flushConntrack drops conntrack entries of a policy so flows re-route after
// a failover instead of sticking to the dead tunnel's NAT binding.
func (e *Engine) flushConntrack(id int) {
	e.mu.Lock()
	cfg, caps := e.rt, e.caps
	e.mu.Unlock()
	if !cfg.Settings.FlushConntrack || !caps.Conntrack || e.DryRun {
		return
	}
	m := fmt.Sprintf("0x%x/0x%x", cfg.Settings.PolicyMark(id), cfg.Settings.MarkMask)
	_, _ = e.R.Run("conntrack", "-D", "-f", "ipv4", "--mark", m)
	if caps.IPv6 {
		_, _ = e.R.Run("conntrack", "-D", "-f", "ipv6", "--mark", m)
	}
}

// SeedHealth fills link-level health for all used tunnels (no network probes).
func (e *Engine) SeedHealth() {
	e.mu.Lock()
	cfg := e.rt
	e.mu.Unlock()
	for _, t := range usedTunnels(cfg) {
		e.mon.Seed(cfg.Settings, t)
	}
}

// ApplyOnce is used by hooks when the daemon is not running.
func (e *Engine) ApplyOnce(reason string) error {
	if err := e.Load(); err != nil {
		return err
	}
	e.DetectCaps()
	e.SeedHealth()
	e.decide()
	return e.Apply(reason)
}

// Plan returns the last generated netfilter plan.
func (e *Engine) Plan() netfilter.Plan {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.plan
}

// Kick schedules an immediate health check + apply in the daemon loop.
func (e *Engine) Kick() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Monitor exposes the health monitor.
func (e *Engine) Monitor() *health.Monitor { return e.mon }

// Decide runs failover selection now (exported for tools and tests).
func (e *Engine) Decide() []int { return e.decide() }

// Caps returns the detected capabilities.
func (e *Engine) Caps() Caps {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.caps
}

// runtime returns the expanded configuration used for routing decisions.
// It is shared and read-only: configuration changes replace it, they never
// modify it (deep copies of large rule lists cost real CPU on a router).
func (e *Engine) runtime() *config.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rt == nil {
		return config.Default()
	}
	return e.rt
}

// domainSet returns a policy's compiled domain rules, compiled once per
// configuration.
func (e *Engine) domainSet(p config.Policy) *match.Set {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s, ok := e.compiled[p.ID]; ok && e.compiledFor == e.rt {
		return s
	}
	if e.compiledFor != e.rt {
		e.compiled, e.compiledFor = map[int]*match.Set{}, e.rt
	}
	s := p.DomainRules()
	e.compiled[p.ID] = s
	return s
}

// UpdateConfig applies fn to a copy of the configuration, then validates,
// saves and applies it.
func (e *Engine) UpdateConfig(fn func(c *config.Config) error) (*config.Config, error) {
	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	c := e.Config()
	if err := fn(c); err != nil {
		return nil, err
	}
	if err := e.SetConfig(c); err != nil {
		return nil, err
	}
	return e.Config(), nil
}
