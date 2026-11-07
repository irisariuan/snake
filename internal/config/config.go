// Package config defines snake's persistent configuration model.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

// WireGuardPrefix names the WireGuard tunnels snake runs itself, beyond
// the firmware's VPN clients: wgx1 ... wgx<MaxWireGuard>. The name is
// also the kernel interface.
const WireGuardPrefix = "wgx"

// MaxWireGuard is the number of WireGuard tunnels snake can run itself.
const MaxWireGuard = 20

// OpenVPNPrefix names the OpenVPN clients snake runs itself: ovx1 ...
// ovx<MaxOpenVPN>, also the interface name.
const OpenVPNPrefix = "ovx"

// MaxOpenVPN is the number of OpenVPN clients snake can run itself.
const MaxOpenVPN = 20

// MaxTunnels is the number of tunnel slots (firmware clients + snake's
// own WireGuard and OpenVPN tunnels): probe marks, probe tables and rule
// priorities are reserved for each.
var MaxTunnels = len(TunnelNames) + MaxWireGuard + MaxOpenVPN

// WireGuardName returns the tunnel name of snake's own WireGuard slot n.
func WireGuardName(n int) string { return WireGuardPrefix + strconv.Itoa(n) }

// WireGuardSlot returns n for "wgx<n>", or 0.
func WireGuardSlot(name string) int { return slot(name, WireGuardPrefix, MaxWireGuard) }

// OpenVPNName returns the tunnel name of snake's own OpenVPN slot n.
func OpenVPNName(n int) string { return OpenVPNPrefix + strconv.Itoa(n) }

// OpenVPNSlot returns n for "ovx<n>", or 0.
func OpenVPNSlot(name string) int { return slot(name, OpenVPNPrefix, MaxOpenVPN) }

// SnakeTunnel reports whether snake runs the tunnel itself (wgx, ovx).
func SnakeTunnel(name string) bool { return WireGuardSlot(name) > 0 || OpenVPNSlot(name) > 0 }

func slot(name, prefix string, max int) int {
	if !strings.HasPrefix(name, prefix) {
		return 0
	}
	d := strings.TrimPrefix(name, prefix)
	n, err := strconv.Atoi(d)
	if err != nil || n < 1 || n > max || strconv.Itoa(n) != d {
		return 0
	}
	return n
}

// IsWireGuard reports whether a tunnel is WireGuard (firmware or snake's own).
func IsWireGuard(name string) bool {
	return strings.HasPrefix(name, "wgc") || WireGuardSlot(name) > 0
}

// TunnelIndex returns a stable 1-based index for a tunnel name, or 0.
// Firmware clients are 1-10, snake's WireGuard tunnels 11-30, its
// OpenVPN clients 31-50.
func TunnelIndex(name string) int {
	for i, n := range TunnelNames {
		if n == name {
			return i + 1
		}
	}
	if n := WireGuardSlot(name); n > 0 {
		return len(TunnelNames) + n
	}
	if n := OpenVPNSlot(name); n > 0 {
		return len(TunnelNames) + MaxWireGuard + n
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
	// DNSProtocol is how the router talks to DNSServer: udp (plain DNS),
	// dot (DNS over TLS, port 853) or doh (DNS over HTTPS, port 443).
	DNSProtocol string `json:"dns_protocol"`
	DNSTLSName  string `json:"dns_tls_name"` // certificate name of DNSServer (dot/doh)
	DNSDoHPath  string `json:"dns_doh_path"` // DoH URL path, default /dns-query
	HijackDNS   bool   `json:"hijack_dns"`   // redirect port 53 from scoped clients to the router
	BlockDoT    bool   `json:"block_dot"`    // block TCP/UDP 853 (DoT/DoQ) from scoped clients
	BlockDoH    bool   `json:"block_doh"`    // block known DoH resolvers on 443 from scoped clients
	BlockQUIC   bool   `json:"block_quic"`   // block UDP 443 from scoped clients
	// SniffSNI routes the scoped clients' HTTPS connections that no set
	// matched by their TLS server name, through snake's transparent SNI
	// proxy, so domain rules also work for devices using DoH/DoT.
	SniffSNI bool `json:"sniff_sni"`
	// ECH (with SniffSNI) is what the SNI proxy does with Encrypted Client
	// Hello connections of the policy's devices, whose real server name
	// is hidden behind a public one: ECHDrop, ECHRelay or ECHPassthrough.
	ECH string `json:"ech"`
	// RefuseECH is the older form of ECH == ECHDrop. It is read when ECH
	// is empty and kept in sync, so older versions keep the behaviour.
	RefuseECH bool   `json:"refuse_ech"`
	IPv6      string `json:"ipv6"`   // tunnel | block | off
	WebRTC    string `json:"webrtc"` // track | off
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
	// ExcludeDevices are never handled by this policy: not routed, not
	// blocked by its drop: rules, not under its leak protection. With no
	// Devices the policy covers every device but these.
	ExcludeDevices []string `json:"exclude_devices"`
	Lists          []string `json:"lists"` // names of rule lists merged into this policy
	Leak           Leak     `json:"leak"`
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
	MarkMask uint32 `json:"mark_mask"`
	// ConnMarkMask holds the policy id in the conntrack mark. It is kept
	// apart from MarkMask: Adaptive QoS writes its category into conntrack
	// marks (0x003f0000), which snake would otherwise restore as a policy
	// mark. Conntrack marks are not read by Broadcom's packet path, so bits
	// that are unsafe in packet marks are fine here.
	ConnMarkMask     uint32 `json:"conn_mark_mask"`
	APIPort          int    `json:"api_port"`
	QueueBase        int    `json:"queue_base"`
	DomainSetTimeout int    `json:"domain_set_timeout"` // seconds, 0 = never expire
	SessionTimeout   int    `json:"session_timeout"`    // WebRTC session window, seconds
	PeerTimeout      int    `json:"peer_timeout"`       // unused: WebRTC peers are sessions now (session_ttl); kept for older versions
	// SessionTTL is how long a session (a device + address pair routed by
	// a session: rule or learned from the device's WebRTC traffic) lasts
	// after the device's last connection to that address, seconds. A new
	// connection renews it.
	SessionTTL      int      `json:"session_ttl"`
	STUNServerTTL   int      `json:"stun_server_ttl"` // learned STUN/TURN server lifetime once idle, seconds
	HealthInterval  int      `json:"health_interval"`
	HandshakeMaxAge int      `json:"handshake_max_age"`
	ProbeTargets    []string `json:"probe_targets"` // host:port, TCP
	ProbeFailures   int      `json:"probe_failures"`
	GeoURL          string   `json:"geo_url"`
	GeoCountryField string   `json:"geo_country_field"`
	GeoIPField      string   `json:"geo_ip_field"`
	GeoInterval     int      `json:"geo_interval"`
	GeoStrict       bool     `json:"geo_strict"` // unknown country counts as failure
	AutoFailback    bool     `json:"auto_failback"`
	FailbackHold    int      `json:"failback_hold"`
	ASNRefresh      int      `json:"asn_refresh"` // hours
	SaveInterval    int      `json:"save_interval"`
	STUNPorts       string   `json:"stun_ports"` // multiport syntax for fallback mode
	DoHCanary       bool     `json:"doh_canary"` // answer Firefox/iCloud Private Relay canaries with NXDOMAIN
	PreResolve      bool     `json:"pre_resolve"`
	FlushConntrack  bool     `json:"flush_conntrack"`
	// LANInterfaces are the iptables -i patterns of client traffic,
	// separated by spaces: the LAN bridges plus the router's VPN servers
	// (WireGuard wgs*, OpenVPN tun21/tun22), whose clients are covered
	// like LAN devices.
	LANInterfaces   string   `json:"lan_interfaces"`
	STUNTestServers []string `json:"stun_test_servers"`
	AutoUpdate      bool     `json:"auto_update"` // install new releases automatically
	UpdateRepo      string   `json:"update_repo"` // GitHub owner/name releases come from
	// Router-wide DoT / DoH blocking: policy (each policy's toggle), always
	// (whole LAN) or never (overrides every policy).
	BlockDoT string `json:"block_dot"`
	BlockDoH string `json:"block_doh"`
	// DNSForwardPort is the preferred encrypted-DNS listener port base.
	// Occupied/reserved ports are replaced by allocated runtime endpoints.
	DNSForwardPort int `json:"dns_forward_port"`
	// SNIProxyPort is the port of the transparent SNI proxy (sniff_sni).
	SNIProxyPort int `json:"sni_proxy_port"`
}

// CurrentVersion is the configuration format version.
//
//	2: (withdrawn) moved the default mark mask to 0x3fc00000.
//	3: moves 0x3fc00000 back to 0x00ff0000: bits 22-29 are Broadcom's
//	   egress port, IPsec and policy-routing fields, and routed traffic
//	   stopped working.
//	4: conntrack marks move to their own bits (conn_mark_mask).
//	5: lan_interfaces is a list and includes the VPN servers by default.
const CurrentVersion = 5

// DefaultLANInterfaces covers the LAN bridges (br0, guest networks) and
// the clients of the router's VPN servers: WireGuard (wgs1...) and OpenVPN
// in tun mode (tun21, tun22). OpenVPN in tap mode is bridged into br0.
const DefaultLANInterfaces = "br+ wgs+ tun2+"

// ClientInterfaces returns the iptables -i patterns of client traffic.
func (s Settings) ClientInterfaces() []string {
	f := strings.FieldsFunc(s.LANInterfaces, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })
	if len(f) == 0 {
		return []string{"br+"}
	}
	return dedup(f)
}

// L2Interface reports whether a pattern names interfaces with Ethernet
// headers, where clients can be matched by MAC address. Routed tunnels
// (VPN servers) carry IP packets only.
func L2Interface(pattern string) bool {
	for _, p := range []string{"wg", "tun", "ppp", "ipsec", "vti"} {
		if strings.HasPrefix(pattern, p) {
			return false
		}
	}
	return true
}

var ifacePatternRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\+?$`)

// Mark bits.
//
// On Broadcom (HND) kernels every bit of skb->mark has a vendor meaning
// (bcm_skb_defines.h): queue 0-4, traffic class 5-10, flow id 11-18, ingress
// priority 19, egress port 20-26, WAN flag 27, IPsec 28, policy routing
// 29-31. Small values in bits 16-18 (flow id, which Merlin's VPN Director
// also uses) are harmless; the higher fields change how the packet is sent.
const (
	DefaultMarkMask uint32 = 0x00ff0000
	// BadMarkMask is the version 2 default that broke routed traffic.
	BadMarkMask uint32 = 0x3fc00000
	// BroadcomReservedMask must not be used: IPsec, WAN flag and policy
	// routing fields, and the upper egress port bits.
	BroadcomReservedMask uint32 = 0xff000000
	// AdaptiveQoSMask is the mark bits Adaptive QoS (bwdpi) classifies with.
	AdaptiveQoSMask uint32 = 0xc03fffff
	// QoSDirMask is the direction bits every Adaptive QoS mark has one of
	// (0x8... download, 0x4... upload). snake's marks never set them, and
	// its ip rules require them clear, so a QoS-marked packet never matches
	// a policy.
	QoSDirMask uint32 = 0xc0000000
	// DefaultConnMarkMask is clear of Adaptive QoS (0xc03fffff).
	DefaultConnMarkMask uint32 = 0x3fc00000
)

func maskShift(m uint32) uint {
	var shift uint
	for m != 0 && m&1 == 0 {
		m >>= 1
		shift++
	}
	return shift
}

// RouteMask is the fwmark mask of snake's ip rules: the policy bits plus
// the Adaptive QoS direction bits, which must be clear.
func (s Settings) RouteMask() uint32 { return s.MarkMask | QoSDirMask }

// ConnMark is a policy's value in the conntrack mark.
func (s Settings) ConnMark(id int) uint32 {
	return uint32(id) << maskShift(s.ConnMarkMask) & s.ConnMarkMask
}

// ConnMarkShift is the bit offset of the policy id inside ConnMarkMask.
func (s Settings) ConnMarkShift() uint { return maskShift(s.ConnMarkMask) }

// MigratedMarkMask returns the conntrack mark bits Load retired (0 if
// none). The caller should save the configuration and clear connections
// still marked in those bits.
func (c *Config) MigratedMarkMask() uint32 { return c.migratedMask }

// Router-wide blocking modes for DoT and DoH.
const (
	BlockPolicy = "policy"
	BlockAlways = "always"
	BlockNever  = "never"
)

// ECH modes: what the SNI proxy does with Encrypted Client Hello
// connections, whose real server name is hidden behind a public one
// (e.g. cloudflare-ech.com).
const (
	// ECHDrop resets them, so a hidden name cannot get past drop: rules.
	ECHDrop = "drop"
	// ECHRelay routes them by the public name, like any other connection:
	// a rule for it sends them through the policy's tunnel (the default).
	ECHRelay = "relay"
	// ECHPassthrough relays them via WAN untouched: the policy's rules,
	// drop: rules included, are not applied to them.
	ECHPassthrough = "passthrough"
)

// Upstream DNS protocols for "resolve via tunnel".
const (
	DNSUDP = "udp"
	DNSDoT = "dot"
	DNSDoH = "doh"
)

// KnownResolverNames maps well-known resolver addresses to the name on
// their certificate, so DoT/DoH work without typing it.
var KnownResolverNames = map[string]string{
	"9.9.9.9":         "dns.quad9.net",
	"149.112.112.112": "dns.quad9.net",
	"9.9.9.11":        "dns11.quad9.net",
	"1.1.1.1":         "cloudflare-dns.com",
	"1.0.0.1":         "cloudflare-dns.com",
	"8.8.8.8":         "dns.google",
	"8.8.4.4":         "dns.google",
	"94.140.14.14":    "dns.adguard-dns.com",
	"94.140.15.15":    "dns.adguard-dns.com",
	"208.67.222.222":  "dns.opendns.com",
	"208.67.220.220":  "dns.opendns.com",
	"194.242.2.2":     "dns.mullvad.net",
}

// Encrypted reports whether policy domains go to the resolver over DoT/DoH
// (through snake's local forwarder) rather than plain DNS.
func (l Leak) Encrypted() bool {
	return l.DNSViaTunnel && (l.DNSProtocol == DNSDoT || l.DNSProtocol == DNSDoH)
}

func blocked(mode string, policy bool) bool {
	switch mode {
	case BlockAlways:
		return true
	case BlockNever:
		return false
	}
	return policy
}

// DoTBlocked is whether DoT is blocked for p's devices.
func (s Settings) DoTBlocked(p Policy) bool { return blocked(s.BlockDoT, p.Leak.BlockDoT) }

// DoHBlocked is whether DoH is blocked for p's devices.
func (s Settings) DoHBlocked(p Policy) bool { return blocked(s.BlockDoH, p.Leak.BlockDoH) }

// Sniffs reports whether p's HTTPS connections are routed by server name:
// only policies that route by domain need it.
func (p Policy) Sniffs() bool { return p.Leak.SniffSNI && p.HasDomains() }

// DoHBlockedAnywhere is whether any device has DoH blocked (the DoH address
// set must be filled).
func (c *Config) DoHBlockedAnywhere() bool {
	switch c.Settings.BlockDoH {
	case BlockAlways:
		return true
	case BlockNever:
		return false
	}
	for _, p := range c.Policies {
		if p.Enabled && p.Leak.BlockDoH {
			return true
		}
	}
	return false
}

// DoHBlockedLANWide is whether DoH is blocked for every LAN device (by
// Settings, or by a destination-only policy). DoH hostnames are then
// blocked in DNS, which applies to the whole LAN.
func (c *Config) DoHBlockedLANWide() bool {
	switch c.Settings.BlockDoH {
	case BlockAlways:
		return true
	case BlockNever:
		return false
	}
	for _, p := range c.Policies {
		if p.Enabled && p.Leak.BlockDoH && len(c.ResolveDevices(p)) == 0 && len(p.ExcludeDevices) == 0 {
			return true
		}
	}
	return false
}

// Config is the root document.
type Config struct {
	Version   int        `json:"version"`
	Settings  Settings   `json:"settings"`
	Devices   []Device   `json:"devices"`
	Groups    []Group    `json:"groups"`
	RuleLists []RuleList `json:"rule_lists"`
	Policies  []Policy   `json:"policies"`
	// WireGuard are tunnels snake creates and runs itself (wgx1...),
	// for more VPNs than the firmware's ten clients.
	WireGuard []WireGuard `json:"wireguard"`
	// OpenVPN are OpenVPN clients snake runs itself (ovx1...).
	OpenVPN []OpenVPN `json:"openvpn"`

	migratedMask uint32 // set by Load, see MigratedMarkMask
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
		MarkMask:         DefaultMarkMask,
		ConnMarkMask:     DefaultConnMarkMask,
		APIPort:          8444,
		QueueBase:        4200,
		DomainSetTimeout: 0,
		SessionTimeout:   120,
		PeerTimeout:      600,
		SessionTTL:       600,
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
		LANInterfaces:    DefaultLANInterfaces,
		STUNTestServers:  []string{"stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"},
		UpdateRepo:       "irisariuan/snake",
		BlockDoT:         BlockPolicy,
		BlockDoH:         BlockPolicy,
		DNSForwardPort:   5350,
		SNIProxyPort:     5340,
	}
}

// DefaultLeak returns full-coverage leak protection.
func DefaultLeak() Leak {
	return Leak{
		DNSViaTunnel: true,
		DNSServer:    "9.9.9.9",
		DNSProtocol:  DNSUDP,
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
	return &Config{Version: CurrentVersion, Settings: DefaultSettings()}
}

// ApplyDefaults fills zero-valued settings, keeping explicit values.
func (c *Config) ApplyDefaults() {
	d := DefaultSettings()
	s := &c.Settings
	if s.MarkMask == 0 {
		s.MarkMask = d.MarkMask
	}
	if s.ConnMarkMask == 0 {
		s.ConnMarkMask = d.ConnMarkMask
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
	setInt(&s.SessionTTL, d.SessionTTL)
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
	if s.UpdateRepo == "" {
		s.UpdateRepo = d.UpdateRepo
	}
	if s.BlockDoT == "" {
		s.BlockDoT = d.BlockDoT
	}
	if s.BlockDoH == "" {
		s.BlockDoH = d.BlockDoH
	}
	setInt(&s.DNSForwardPort, d.DNSForwardPort)
	setInt(&s.SNIProxyPort, d.SNIProxyPort)
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
// occupy the top of the mark range so they never collide with policy ids:
// the firmware clients the top ten values, snake's own tunnels the values
// below them.
func (s Settings) ProbeMark(tunnel string) uint32 {
	return s.probeValue(TunnelIndex(tunnel)) << s.MarkShift() & s.MarkMask
}

func (s Settings) probeValue(idx int) uint32 {
	n := len(TunnelNames)
	if idx <= n {
		return s.MaxMarkValue() - uint32(n) + uint32(idx)
	}
	return s.MaxMarkValue() - uint32(idx)
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

// NormalizeClient validates a device entry: a MAC address, an IP address or
// a subnet (for VPN server clients and other routed clients, which have no
// MAC address at the router). It returns the canonical form.
func NormalizeClient(s string) (string, error) {
	s = strings.TrimSpace(s)
	if m, err := NormalizeMAC(s); err == nil {
		return m, nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.Unmap().String(), nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		p = p.Masked()
		if p.Addr().Is4In6() {
			return "", fmt.Errorf("invalid device %q: use the IPv4 form", s)
		}
		return p.String(), nil
	}
	return "", fmt.Errorf("invalid device %q (MAC address, IP address or subnet)", s)
}

// ClientMAC reports whether a normalized device entry is a MAC address.
func ClientMAC(s string) bool {
	_, err := NormalizeMAC(s)
	return err == nil
}

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
		p.Domains = dedupKeepComments(mapStr(match.Lines(p.Domains), normalizeRule))
		p.CIDRs = dedup(mapStr(p.CIDRs, strings.TrimSpace))
		p.Devices = dedup(mapStr(p.Devices, normalizeDevice))
		p.ExcludeDevices = dedup(mapStr(p.ExcludeDevices, normalizeDevice))
		p.Tunnels = dedup(mapStr(p.Tunnels, func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }))
		p.ExpectedCountry = strings.ToUpper(strings.TrimSpace(p.ExpectedCountry))
		sort.Ints(p.ASNs)
		p.ASNs = dedupInt(p.ASNs)
		p.Leak.DNSServer = strings.TrimSpace(p.Leak.DNSServer)
		p.Leak.DNSProtocol = strings.ToLower(strings.TrimSpace(p.Leak.DNSProtocol))
		if p.Leak.DNSProtocol == "" {
			p.Leak.DNSProtocol = DNSUDP
		}
		p.Leak.DNSTLSName = strings.ToLower(strings.TrimSpace(p.Leak.DNSTLSName))
		if p.Leak.DNSTLSName == "" && p.Leak.DNSProtocol != DNSUDP {
			p.Leak.DNSTLSName = KnownResolverNames[p.Leak.DNSServer]
		}
		p.Leak.DNSDoHPath = strings.TrimSpace(p.Leak.DNSDoHPath)
		p.Leak.ECH = strings.ToLower(strings.TrimSpace(p.Leak.ECH))
		if p.Leak.ECH == "" {
			p.Leak.ECH = ECHRelay
			if p.Leak.RefuseECH {
				p.Leak.ECH = ECHDrop
			}
		}
		p.Leak.RefuseECH = p.Leak.ECH == ECHDrop
		if p.Leak.DNSProtocol == DNSDoH && p.Leak.DNSDoHPath == "" {
			p.Leak.DNSDoHPath = "/dns-query"
		}
		if p.ASNs == nil {
			p.ASNs = []int{}
		}
		p.Lists = dedup(mapStr(p.Lists, strings.TrimSpace))
	}
	for i := range c.RuleLists {
		l := &c.RuleLists[i]
		l.Name = strings.TrimSpace(l.Name)
		l.Domains = dedupKeepComments(mapStr(match.Lines(l.Domains), normalizeRule))
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
	c.normalizeSnakeTunnels()
	if c.Devices == nil {
		c.Devices = []Device{}
	}
	for i := range c.Groups {
		c.Groups[i].Name = strings.TrimSpace(c.Groups[i].Name)
		c.Groups[i].MACs = dedup(mapStr(c.Groups[i].MACs, func(s string) string {
			if m, err := NormalizeClient(s); err == nil {
				return m
			}
			return strings.TrimSpace(s)
		}))
	}
	for i := range c.Devices {
		if m, err := NormalizeClient(c.Devices[i].MAC); err == nil {
			c.Devices[i].MAC = m
		}
	}
}

func normalizeDevice(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "group:") {
		return s
	}
	if m, err := NormalizeClient(s); err == nil {
		return m
	}
	return s
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
	} else if s.MarkMask&BroadcomReservedMask != 0 {
		add("mark_mask 0x%08x uses bits 24-31, which Broadcom routers use for egress port, IPsec and policy routing (routed traffic breaks); use 0x%08x", s.MarkMask, DefaultMarkMask)
	}
	cm := s.ConnMarkMask
	switch {
	case cm == 0 || (cm>>maskShift(cm))&(cm>>maskShift(cm)+1) != 0:
		add("conn_mark_mask must be contiguous bits")
	case cm>>maskShift(cm) < s.MaxMarkValue():
		add("conn_mark_mask must have at least as many bits as mark_mask")
	case cm&AdaptiveQoSMask != 0:
		add("conn_mark_mask must not overlap Adaptive QoS bits (0x%08x)", AdaptiveQoSMask)
	}
	// ipset's maximum timeout.
	for _, t := range []struct {
		name string
		v    int
	}{{"session_timeout", s.SessionTimeout}, {"peer_timeout", s.PeerTimeout}, {"session_ttl", s.SessionTTL}, {"stun_server_ttl", s.STUNServerTTL}, {"domain_set_timeout", s.DomainSetTimeout}} {
		if t.v > 2147483 {
			add("%s must be at most 2147483 seconds", t.name)
		}
	}
	if s.APIPort < 1 || s.APIPort > 65534 {
		add("api_port out of range")
	}
	for name, v := range map[string]string{"block_dot": s.BlockDoT, "block_doh": s.BlockDoH} {
		switch v {
		case "", BlockPolicy, BlockAlways, BlockNever:
		default:
			add("%s must be policy, always or never", name)
		}
	}
	if len(strings.Fields(strings.NewReplacer(",", " ").Replace(s.LANInterfaces))) == 0 {
		add("lan_interfaces needs at least one interface pattern")
	}
	for _, p := range s.ClientInterfaces() {
		if !ifacePatternRe.MatchString(p) {
			add("lan_interfaces: %q is not an interface name or pattern (e.g. br+, wgs1)", p)
		}
	}
	if s.DNSForwardPort < 1024 || s.DNSForwardPort > 65000 {
		add("dns_forward_port must be between 1024 and 65000")
	}
	switch p := s.SNIProxyPort; {
	case p < 1024 || p > 65535:
		add("sni_proxy_port must be between 1024 and 65535")
	case p == s.APIPort:
		add("sni_proxy_port must differ from api_port")
	case p > s.DNSForwardPort && p <= s.DNSForwardPort+s.MaxPolicyID():
		add("sni_proxy_port %d is inside the DoT/DoH forwarder range %d-%d", p, s.DNSForwardPort+1, s.DNSForwardPort+s.MaxPolicyID())
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
			if _, err := NormalizeClient(m); err != nil {
				add("group %s: %v", g.Name, err)
			}
		}
	}
	for _, d := range c.Devices {
		if _, err := NormalizeClient(d.MAC); err != nil {
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
	snakeIDs := c.validateSnakeTunnels(add)
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
			add("%sat least one tunnel is required", pre)
		}
		for _, t := range p.Tunnels {
			switch {
			case TunnelIndex(t) == 0:
				add(pre+"unknown tunnel %q", t)
			case SnakeTunnel(t) && !snakeIDs[t]:
				add(pre+"tunnel %q is not set up (add it under Tunnels)", t)
			}
		}
		if p.ExpectedCountry != "" && !ccRe.MatchString(p.ExpectedCountry) {
			add(pre+"expected_country %q must be a 2-letter code", p.ExpectedCountry)
		}
		for _, le := range compileErrs(p.Domains) {
			add(pre+"rule %q: %s", le.Rule, le.Error)
		}
		// share= options name groups that must exist.
		set := match.MustCompile(c.Expand(p).Domains)
		var opts []match.Opts
		for _, sp := range set.Session {
			opts = append(opts, sp.Opts)
		}
		for _, r := range set.Routes {
			for _, a := range r.Branches() {
				opts = append(opts, a.Opts)
			}
		}
		for _, dp := range set.Drop {
			opts = append(opts, dp.Opts)
		}
		for _, o := range opts {
			for _, sh := range o.Share {
				if sh != match.ShareGlobal && !match.ShareDevice(sh) && !groups[sh] {
					add(pre+"share=%s: no device group with that name", sh)
				}
			}
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
		inc := map[string]bool{}
		for _, d := range p.Devices {
			inc[d] = true
		}
		for _, d := range append(append([]string(nil), p.Devices...), p.ExcludeDevices...) {
			if strings.HasPrefix(d, "group:") {
				if !groups[strings.TrimPrefix(d, "group:")] {
					add(pre+"unknown group %q", d)
				}
			} else if _, err := NormalizeClient(d); err != nil {
				add(pre+"%v", err)
			}
		}
		for _, d := range p.ExcludeDevices {
			if inc[d] {
				add(pre+"%s is both included and excluded", d)
			}
		}
		if ep := c.Expand(p); !ep.HasDomains() && !ep.HasDrops() && len(ep.ASNs)+len(ep.CIDRs)+len(p.Devices) == 0 {
			add("%sneeds at least one domain, ASN, CIDR, device or drop: rule", pre)
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
		switch p.Leak.ECH {
		case "", ECHDrop, ECHRelay, ECHPassthrough:
		default:
			add(pre+"ech mode %q invalid (drop, relay or passthrough)", p.Leak.ECH)
		}
		if p.Leak.DNSViaTunnel {
			if ip := net.ParseIP(p.Leak.DNSServer); ip == nil || ip.To4() == nil {
				add("%sdns_server must be an IPv4 address when dns_via_tunnel is on", pre)
			}
		}
		switch p.Leak.DNSProtocol {
		case "", DNSUDP:
		case DNSDoT, DNSDoH:
			if p.Leak.DNSViaTunnel && p.Leak.DNSTLSName == "" {
				add("%sdns_tls_name is required for %s (the name on %s's certificate, e.g. dns.quad9.net)", pre, p.Leak.DNSProtocol, p.Leak.DNSServer)
			}
			if p.Leak.DNSProtocol == DNSDoH && !strings.HasPrefix(p.Leak.DNSDoHPath, "/") {
				add("%sdns_doh_path must start with /", pre)
			}
		default:
			add("%sdns_protocol %q invalid (udp, dot or doh)", pre, p.Leak.DNSProtocol)
		}
		if p.Leak.Encrypted() && s.DNSForwardPort+p.ID > 65535 {
			add("%sdns_forward_port + policy id exceeds 65535", pre)
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

// ResolveDevices expands groups into device entries: MAC addresses, IP
// addresses and subnets.
func (c *Config) ResolveDevices(p Policy) []string { return c.resolve(p.Devices) }

// ResolveExcluded expands the policy's excluded devices.
func (c *Config) ResolveExcluded(p Policy) []string { return c.resolve(p.ExcludeDevices) }

func (c *Config) resolve(devices []string) []string {
	var out []string
	for _, d := range devices {
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

// HasSessions reports whether the policy has session: rules.
func (p Policy) HasSessions() bool {
	for _, d := range p.Domains {
		r := match.StripComment(d)
		if match.IsRoute(d) || (len(r) >= len("session") && strings.EqualFold(r[:len("session")], "session") && len(r) > 7 && (r[7] == ':' || r[7] == '[')) {
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
	return len(rule) >= len("drop") && strings.EqualFold(rule[:4], "drop") && len(rule) > 4 && (rule[4] == ':' || rule[4] == '[')
}

// DomainRules compiles the policy's domain rules.
func (p Policy) DomainRules() *match.Set { return match.MustCompile(p.Domains) }

// HasDestinations reports whether the policy matches on destination.
func (p Policy) HasDestinations() bool {
	return p.HasDomains() || len(p.ASNs)+len(p.CIDRs) > 0
}

// Scope describes the policy match mode for display.
func (p Policy) Scope() string {
	if len(p.ExcludeDevices) > 0 && len(p.Devices) == 0 && p.HasDestinations() {
		return "destinations, some devices excluded"
	}
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
	if c.Version < 4 {
		// Before version 4 conntrack marks used the packet-mark bits.
		c.migratedMask = c.Settings.MarkMask
		if c.Version == 2 && c.Settings.MarkMask == BadMarkMask {
			c.Settings.MarkMask = DefaultMarkMask
		}
	}
	if c.Version < 5 && strings.TrimSpace(c.Settings.LANInterfaces) == "br+" {
		// The old default: VPN server clients join the LAN.
		c.Settings.LANInterfaces = DefaultLANInterfaces
	}
	if c.Version < CurrentVersion {
		c.Version = CurrentVersion
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
