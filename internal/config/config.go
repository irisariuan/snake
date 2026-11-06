// Package config defines snake's persistent configuration model.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/irisariuan/snake/internal/match"
)

// Tunnel names supported by Asuswrt-Merlin.
var TunnelNames = []string{
	"wgc1", "wgc2", "wgc3", "wgc4", "wgc5",
	"ovpnc1", "ovpnc2", "ovpnc3", "ovpnc4", "ovpnc5",
}

// TunnelIndex returns a stable 1-based index for a tunnel name, or 0.
func TunnelIndex(name string) int {
	for i, n := range TunnelNames {
		if n == name {
			return i + 1
		}
	}
	return 0
}

// TunnelInterface maps a Merlin VPN client name to its kernel interface.
func TunnelInterface(name string) string {
	if strings.HasPrefix(name, "ovpnc") {
		return "tun1" + strings.TrimPrefix(name, "ovpnc")
	}
	return name
}

const (
	IPv6Tunnel = "tunnel" // route IPv6 via tunnel when it has IPv6, otherwise block
	IPv6Block  = "block"  // always block IPv6 for policy traffic
	IPv6Off    = "off"    // do nothing (IPv6 may leak)

	WebRTCOff   = "off"   // no WebRTC handling
	WebRTCTrack = "track" // session-affinity tracking (NFQUEUE STUN learning, port fallback)
)

// Leak holds per-policy leak protection toggles.
type Leak struct {
	DNSViaTunnel bool   `json:"dns_via_tunnel"` // resolve policy domains with DNSServer through the tunnel
	DNSServer    string `json:"dns_server"`     // resolver reached through the tunnel
	HijackDNS    bool   `json:"hijack_dns"`     // redirect port 53 from scoped clients to the router
	BlockDoT     bool   `json:"block_dot"`      // block TCP/UDP 853 (DoT/DoQ) from scoped clients
	BlockDoH     bool   `json:"block_doh"`      // block known DoH resolvers on 443 from scoped clients
	BlockQUIC    bool   `json:"block_quic"`     // block UDP 443 from scoped clients
	IPv6         string `json:"ipv6"`           // tunnel | block | off
	WebRTC       string `json:"webrtc"`         // track | off
}

// Policy routes matched traffic through an ordered list of tunnels.
type Policy struct {
	ID              int      `json:"id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Tunnels         []string `json:"tunnels"`          // ordered by priority, failover candidates
	KillSwitch      bool     `json:"kill_switch"`      // drop instead of WAN when no tunnel healthy
	ExpectedCountry string   `json:"expected_country"` // ISO 3166 alpha-2, optional
	Domains         []string `json:"domains"`          // domain rules, see package match for the format
	IgnoreCNAME     bool     `json:"ignore_cname"`     // match the queried name only, not its CNAME chain
	ASNs            []int    `json:"asns"`
	CIDRs           []string `json:"cidrs"`
	Devices         []string `json:"devices"` // MAC addresses or "group:<name>"
	Lists           []string `json:"lists"`   // names of rule lists merged into this policy
	Leak            Leak     `json:"leak"`
}

// RuleList is a reusable, importable/exportable set of rules (a .rules file).
type RuleList struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Source      string   `json:"source"` // URL it was imported from (for refresh)
	Domains     []string `json:"domains"`
	ASNs        []int    `json:"asns"`
	CIDRs       []string `json:"cidrs"`
}

// Group is a named set of devices.
type Group struct {
	Name string   `json:"name"`
	MACs []string `json:"macs"`
}

// Device is a friendly name for a MAC.
type Device struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

// Settings are global tunables.
type Settings struct {
	MarkMask         uint32   `json:"mark_mask"`
	APIPort          int      `json:"api_port"`
	QueueBase        int      `json:"queue_base"`
	DomainSetTimeout int      `json:"domain_set_timeout"` // seconds, 0 = never expire
	SessionTimeout   int      `json:"session_timeout"`    // WebRTC session window, seconds
	PeerTimeout      int      `json:"peer_timeout"`       // learned WebRTC peer lifetime, seconds
	STUNServerTTL    int      `json:"stun_server_ttl"`    // learned STUN/TURN server lifetime once idle, seconds
	HealthInterval   int      `json:"health_interval"`
	HandshakeMaxAge  int      `json:"handshake_max_age"`
	ProbeTargets     []string `json:"probe_targets"` // host:port, TCP
	ProbeFailures    int      `json:"probe_failures"`
	GeoURL           string   `json:"geo_url"`
	GeoCountryField  string   `json:"geo_country_field"`
	GeoIPField       string   `json:"geo_ip_field"`
	GeoInterval      int      `json:"geo_interval"`
	GeoStrict        bool     `json:"geo_strict"` // unknown country counts as failure
	AutoFailback     bool     `json:"auto_failback"`
	FailbackHold     int      `json:"failback_hold"`
	ASNRefresh       int      `json:"asn_refresh"` // hours
	SaveInterval     int      `json:"save_interval"`
	STUNPorts        string   `json:"stun_ports"` // multiport syntax for fallback mode
	DoHCanary        bool     `json:"doh_canary"` // answer Firefox/iCloud Private Relay canaries with NXDOMAIN
	PreResolve       bool     `json:"pre_resolve"`
	FlushConntrack   bool     `json:"flush_conntrack"`
	LANInterfaces    string   `json:"lan_interfaces"` // iptables -i pattern
	STUNTestServers  []string `json:"stun_test_servers"`
}

// Config is the root document.
type Config struct {
	Version   int        `json:"version"`
	Settings  Settings   `json:"settings"`
	Devices   []Device   `json:"devices"`
	Groups    []Group    `json:"groups"`
	RuleLists []RuleList `json:"rule_lists"`
	Policies  []Policy   `json:"policies"`
}

// List returns a rule list by name.
func (c *Config) List(name string) (RuleList, bool) {
	for _, l := range c.RuleLists {
		if l.Name == name {
			return l, true
		}
	}
	return RuleList{}, false
}

// Expand returns the policy with the content of its rule lists merged in.
// Exclusions from any list apply to the whole policy.
func (c *Config) Expand(p Policy) Policy {
	q := p
	q.Domains = append([]string(nil), p.Domains...)
	q.ASNs = append([]int(nil), p.ASNs...)
	q.CIDRs = append([]string(nil), p.CIDRs...)
	for _, n := range p.Lists {
		l, ok := c.List(n)
		if !ok {
			continue
		}
		q.Domains = append(q.Domains, l.Domains...)
		q.ASNs = append(q.ASNs, l.ASNs...)
		q.CIDRs = append(q.CIDRs, l.CIDRs...)
	}
	q.Domains = dedupKeepComments(q.Domains)
	sort.Ints(q.ASNs)
	q.ASNs = dedupInt(q.ASNs)
	q.CIDRs = dedup(q.CIDRs)
	q.Lists = nil
	return q
}

// Runtime returns a copy with every policy expanded; the engine works on it.
func (c *Config) Runtime() *Config {
	cp := *c
	cp.Policies = make([]Policy, len(c.Policies))
	for i, p := range c.Policies {
		cp.Policies[i] = c.Expand(p)
	}
	return &cp
}

func dedupKeepComments(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.HasPrefix(s, "#") || !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// DefaultSettings returns sane defaults.
func DefaultSettings() Settings {
	return Settings{
		MarkMask:         0x00ff0000,
		APIPort:          8444,
		QueueBase:        4200,
		DomainSetTimeout: 0,
		SessionTimeout:   120,
		PeerTimeout:      600,
		STUNServerTTL:    86400,
		HealthInterval:   15,
		HandshakeMaxAge:  180,
		ProbeTargets:     []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"},
		ProbeFailures:    3,
		GeoURL:           "https://ipinfo.io/json",
		GeoCountryField:  "country",
		GeoIPField:       "ip",
		GeoInterval:      600,
		AutoFailback:     true,
		FailbackHold:     120,
		ASNRefresh:       24,
		SaveInterval:     1800,
		STUNPorts:        "3478,3479,5349,19302:19309",
		DoHCanary:        true,
		PreResolve:       true,
		FlushConntrack:   true,
		LANInterfaces:    "br+",
		STUNTestServers:  []string{"stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"},
	}
}

// DefaultLeak returns full-coverage leak protection.
func DefaultLeak() Leak {
	return Leak{
		DNSViaTunnel: true,
		DNSServer:    "9.9.9.9",
		HijackDNS:    true,
		BlockDoT:     true,
		BlockDoH:     true,
		BlockQUIC:    false,
		IPv6:         IPv6Tunnel,
		WebRTC:       WebRTCTrack,
	}
}

// Default returns an empty configuration.
func Default() *Config {
	return &Config{Version: 1, Settings: DefaultSettings()}
}

// ApplyDefaults fills zero-valued settings, keeping explicit values.
func (c *Config) ApplyDefaults() {
	d := DefaultSettings()
	s := &c.Settings
	if s.MarkMask == 0 {
		s.MarkMask = d.MarkMask
	}
	setInt := func(v *int, def int) {
		if *v <= 0 {
			*v = def
		}
	}
	setInt(&s.APIPort, d.APIPort)
	setInt(&s.QueueBase, d.QueueBase)
	setInt(&s.SessionTimeout, d.SessionTimeout)
	setInt(&s.PeerTimeout, d.PeerTimeout)
	setInt(&s.STUNServerTTL, d.STUNServerTTL)
	setInt(&s.HealthInterval, d.HealthInterval)
	setInt(&s.HandshakeMaxAge, d.HandshakeMaxAge)
	setInt(&s.ProbeFailures, d.ProbeFailures)
	setInt(&s.GeoInterval, d.GeoInterval)
	setInt(&s.FailbackHold, d.FailbackHold)
	setInt(&s.ASNRefresh, d.ASNRefresh)
	setInt(&s.SaveInterval, d.SaveInterval)
	if s.DomainSetTimeout < 0 {
		s.DomainSetTimeout = 0
	}
	if len(s.ProbeTargets) == 0 {
		s.ProbeTargets = d.ProbeTargets
	}
	if s.GeoURL == "" {
		s.GeoURL, s.GeoCountryField, s.GeoIPField = d.GeoURL, d.GeoCountryField, d.GeoIPField
	}
	if s.STUNPorts == "" {
		s.STUNPorts = d.STUNPorts
	}
	if s.LANInterfaces == "" {
		s.LANInterfaces = d.LANInterfaces
	}
	if len(s.STUNTestServers) == 0 {
		s.STUNTestServers = d.STUNTestServers
	}
	for i := range c.Policies {
		p := &c.Policies[i]
		if p.Leak.IPv6 == "" {
			p.Leak.IPv6 = IPv6Tunnel
		}
		if p.Leak.WebRTC == "" {
			p.Leak.WebRTC = WebRTCOff
		}
	}
}

// MarkShift is the bit offset of the policy id inside MarkMask.
func (s Settings) MarkShift() uint {
	m := s.MarkMask
	var shift uint
	for m != 0 && m&1 == 0 {
		m >>= 1
		shift++
	}
	return shift
}

// MaxMarkValue is the largest id representable within MarkMask.
func (s Settings) MaxMarkValue() uint32 {
	return s.MarkMask >> s.MarkShift()
}

// PolicyMark returns the fwmark for a policy id.
func (s Settings) PolicyMark(id int) uint32 {
	return uint32(id) << s.MarkShift() & s.MarkMask
}

// ProbeMark returns the fwmark used by health probes for a tunnel. Probe marks
// occupy the top of the mark range so they never collide with policy ids.
func (s Settings) ProbeMark(tunnel string) uint32 {
	idx := TunnelIndex(tunnel)
	return (s.MaxMarkValue() - uint32(len(TunnelNames)) + uint32(idx)) << s.MarkShift() & s.MarkMask
}

// MaxPolicyID is the largest policy id allowed.
func (s Settings) MaxPolicyID() int {
	max := int(s.MaxMarkValue()) - len(TunnelNames)
	if max > 200 {
		max = 200 // routing tables 1000+id, priorities 5200+id
	}
	return max
}

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9 _.\-+]{1,40}$`)
	ccRe   = regexp.MustCompile(`^[A-Z]{2}$`)
)

// NormalizeMAC lowercases and validates a MAC address.
func NormalizeMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC %q", s)
	}
	return hw.String(), nil
}

// NormalizeDomain turns a plain domain (as used by Domain VPN Routing, where
// "*.example.com" means "example.com and its subdomains") into a suffix rule.
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	return strings.TrimSuffix(s, ".")
}

// ParseASN accepts "AS2906", "as2906" or "2906".
func ParseASN(s string) (int, error) {
	s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v == 0 || uint64(int(v)) != v {
		return 0, fmt.Errorf("invalid ASN %q", s)
	}
	return int(v), nil
}

// Normalize cleans user input in place (dedup, lowercase) and assigns ids.
func (c *Config) Normalize() {
	used := map[int]bool{}
	for _, p := range c.Policies {
		if p.ID > 0 {
			used[p.ID] = true
		}
	}
	next := 1
	for i := range c.Policies {
		p := &c.Policies[i]
		if p.ID <= 0 || (used[p.ID] && countID(c.Policies[:i], p.ID) > 0) {
			for used[next] {
				next++
			}
			p.ID = next
			used[next] = true
		}
		p.Name = strings.TrimSpace(p.Name)
		p.Domains = dedupKeepComments(mapStr(p.Domains, normalizeRule))
		p.CIDRs = dedup(mapStr(p.CIDRs, strings.TrimSpace))
		p.Devices = dedup(mapStr(p.Devices, func(s string) string {
			s = strings.TrimSpace(s)
			if strings.HasPrefix(s, "group:") {
				return s
			}
			if m, err := NormalizeMAC(s); err == nil {
				return m
			}
			return s
		}))
		p.Tunnels = dedup(mapStr(p.Tunnels, func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }))
		p.ExpectedCountry = strings.ToUpper(strings.TrimSpace(p.ExpectedCountry))
		sort.Ints(p.ASNs)
		p.ASNs = dedupInt(p.ASNs)
		p.Leak.DNSServer = strings.TrimSpace(p.Leak.DNSServer)
		if p.ASNs == nil {
			p.ASNs = []int{}
		}
		p.Lists = dedup(mapStr(p.Lists, strings.TrimSpace))
	}
	for i := range c.RuleLists {
		l := &c.RuleLists[i]
		l.Name = strings.TrimSpace(l.Name)
		l.Domains = dedupKeepComments(mapStr(l.Domains, normalizeRule))
		l.CIDRs = dedup(mapStr(l.CIDRs, strings.TrimSpace))
		sort.Ints(l.ASNs)
		l.ASNs = dedupInt(l.ASNs)
		if l.ASNs == nil {
			l.ASNs = []int{}
		}
	}
	if c.RuleLists == nil {
		c.RuleLists = []RuleList{}
	}
	// Empty lists serialise as [] rather than null for API clients.
	if c.Policies == nil {
		c.Policies = []Policy{}
	}
	if c.Groups == nil {
		c.Groups = []Group{}
	}
	if c.Devices == nil {
		c.Devices = []Device{}
	}
	for i := range c.Groups {
		c.Groups[i].Name = strings.TrimSpace(c.Groups[i].Name)
		c.Groups[i].MACs = dedup(mapStr(c.Groups[i].MACs, func(s string) string {
			if m, err := NormalizeMAC(s); err == nil {
				return m
			}
			return strings.TrimSpace(s)
		}))
	}
	for i := range c.Devices {
		if m, err := NormalizeMAC(c.Devices[i].MAC); err == nil {
			c.Devices[i].MAC = m
		}
	}
}

func countID(ps []Policy, id int) int {
	n := 0
	for _, p := range ps {
		if p.ID == id {
			n++
		}
	}
	return n
}

// Validate returns all problems found in the configuration.
func (c *Config) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	s := c.Settings
	if s.MarkMask == 0 || s.MaxMarkValue() < 32 {
		add("mark_mask must contain at least 6 contiguous bits")
	} else if (s.MarkMask>>s.MarkShift())&(s.MarkMask>>s.MarkShift()+1) != 0 {
		add("mark_mask bits must be contiguous")
	}
	// ipset's maximum timeout.
	for _, t := range []struct {
		name string
		v    int
	}{{"session_timeout", s.SessionTimeout}, {"peer_timeout", s.PeerTimeout}, {"stun_server_ttl", s.STUNServerTTL}, {"domain_set_timeout", s.DomainSetTimeout}} {
		if t.v > 2147483 {
			add("%s must be at most 2147483 seconds", t.name)
		}
	}
	if s.APIPort < 1 || s.APIPort > 65534 {
		add("api_port out of range")
	}
	for _, t := range s.ProbeTargets {
		if _, _, err := net.SplitHostPort(t); err != nil {
			add("probe target %q must be host:port", t)
		}
	}
	groups := map[string]bool{}
	for _, g := range c.Groups {
		if !nameRe.MatchString(g.Name) {
			add("group name %q invalid", g.Name)
		}
		if groups[g.Name] {
			add("duplicate group %q", g.Name)
		}
		groups[g.Name] = true
		for _, m := range g.MACs {
			if _, err := NormalizeMAC(m); err != nil {
				add("group %s: %v", g.Name, err)
			}
		}
	}
	for _, d := range c.Devices {
		if _, err := NormalizeMAC(d.MAC); err != nil {
			add("device %s: %v", d.Name, err)
		}
	}
	lists := map[string]bool{}
	for _, l := range c.RuleLists {
		if !nameRe.MatchString(l.Name) {
			add("rule list name %q invalid (1-40 chars: letters, digits, space, _.-+)", l.Name)
		}
		if lists[l.Name] {
			add("duplicate rule list %q", l.Name)
		}
		lists[l.Name] = true
		for _, le := range compileErrs(l.Domains) {
			add("rule list %s: rule %q: %s", l.Name, le.Rule, le.Error)
		}
		for _, cidr := range l.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil && net.ParseIP(cidr) == nil {
				add("rule list %s: invalid CIDR %q", l.Name, cidr)
			}
		}
	}
	names := map[string]bool{}
	ids := map[int]bool{}
	for _, p := range c.Policies {
		pre := "policy " + p.Name + ": "
		if !nameRe.MatchString(p.Name) {
			add("policy name %q invalid (1-40 chars: letters, digits, space, _.-+)", p.Name)
		}
		if names[p.Name] {
			add("duplicate policy name %q", p.Name)
		}
		names[p.Name] = true
		if p.ID < 1 || p.ID > s.MaxPolicyID() {
			add(pre+"id %d out of range 1-%d", p.ID, s.MaxPolicyID())
		}
		if ids[p.ID] {
			add(pre+"duplicate id %d", p.ID)
		}
		ids[p.ID] = true
		if len(p.Tunnels) == 0 {
			add(pre + "at least one tunnel is required")
		}
		for _, t := range p.Tunnels {
			if TunnelIndex(t) == 0 {
				add(pre+"unknown tunnel %q", t)
			}
		}
		if p.ExpectedCountry != "" && !ccRe.MatchString(p.ExpectedCountry) {
			add(pre+"expected_country %q must be a 2-letter code", p.ExpectedCountry)
		}
		for _, le := range compileErrs(p.Domains) {
			add(pre+"rule %q: %s", le.Rule, le.Error)
		}
		for _, n := range p.Lists {
			if !lists[n] {
				add(pre+"unknown rule list %q", n)
			}
		}
		for _, cidr := range p.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil && net.ParseIP(cidr) == nil {
				add(pre+"invalid CIDR %q", cidr)
			}
		}
		for _, d := range p.Devices {
			if strings.HasPrefix(d, "group:") {
				if !groups[strings.TrimPrefix(d, "group:")] {
					add(pre+"unknown group %q", d)
				}
			} else if _, err := NormalizeMAC(d); err != nil {
				add(pre+"%v", err)
			}
		}
		if ep := c.Expand(p); !ep.HasDomains() && !ep.HasDrops() && len(ep.ASNs)+len(ep.CIDRs)+len(p.Devices) == 0 {
			add(pre + "needs at least one domain, ASN, CIDR, device or drop: rule")
		}
		switch p.Leak.IPv6 {
		case IPv6Tunnel, IPv6Block, IPv6Off:
		default:
			add(pre+"ipv6 mode %q invalid", p.Leak.IPv6)
		}
		switch p.Leak.WebRTC {
		case WebRTCTrack, WebRTCOff:
		default:
			add(pre+"webrtc mode %q invalid", p.Leak.WebRTC)
		}
		if p.Leak.DNSViaTunnel {
			if ip := net.ParseIP(p.Leak.DNSServer); ip == nil || ip.To4() == nil {
				add(pre + "dns_server must be an IPv4 address when dns_via_tunnel is on")
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func compileErrs(rules []string) []match.LineError {
	_, errs := match.Compile(rules)
	return errs
}

// ResolveDevices expands groups into MAC addresses.
func (c *Config) ResolveDevices(p Policy) []string {
	var out []string
	for _, d := range p.Devices {
		if strings.HasPrefix(d, "group:") {
			name := strings.TrimPrefix(d, "group:")
			for _, g := range c.Groups {
				if g.Name == name {
					out = append(out, g.MACs...)
				}
			}
			continue
		}
		out = append(out, d)
	}
	return dedup(out)
}

func normalizeRule(s string) string {
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "#") {
		return t // keep comment lines
	}
	return match.Normalize(s)
}

// HasDomains reports whether the policy has at least one domain rule
// (comment lines do not count).
// HasDomains reports whether the policy routes by domain (drop: rules do
// not count: they block, they do not decide what the policy routes).
func (p Policy) HasDomains() bool {
	for _, d := range p.Domains {
		if r := match.StripComment(d); r != "" && !isDrop(r) {
			return true
		}
	}
	return false
}

// HasDrops reports whether the policy has drop: rules.
func (p Policy) HasDrops() bool {
	for _, d := range p.Domains {
		if isDrop(match.StripComment(d)) {
			return true
		}
	}
	return false
}

func isDrop(rule string) bool {
	return len(rule) >= len(match.DropPrefix) && strings.EqualFold(rule[:len(match.DropPrefix)], match.DropPrefix)
}

// DomainRules compiles the policy's domain rules.
func (p Policy) DomainRules() *match.Set { return match.MustCompile(p.Domains) }

// HasDestinations reports whether the policy matches on destination.
func (p Policy) HasDestinations() bool {
	return p.HasDomains() || len(p.ASNs)+len(p.CIDRs) > 0
}

// Scope describes the policy match mode for display.
func (p Policy) Scope() string {
	switch {
	case len(p.Devices) > 0 && p.HasDestinations():
		return "devices+destinations"
	case len(p.Devices) > 0:
		return "whole-device"
	default:
		return "destinations"
	}
}

// Load reads the config file, returning defaults if it does not exist.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.ApplyDefaults()
	return c, nil
}

// Save atomically writes the config file.
func Save(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func mapStr(in []string, f func(string) string) []string {
	out := make([]string, 0, len(in)) // never nil
	for _, s := range in {
		if v := f(s); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupInt(in []int) []int {
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
