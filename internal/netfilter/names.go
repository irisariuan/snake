// Package netfilter builds and applies iptables/ipset state for snake.
package netfilter

import "fmt"

// Set kinds.
const (
	KindDomain  = "d" // populated by dnsmasq in real time
	KindNet     = "n" // static CIDRs + ASN prefixes
	KindSession = "s" // WebRTC session window: client IPs with a live policy session
	KindPeer    = "r" // WebRTC peers learned from STUN (ICE connectivity checks)
	KindServer  = "t" // STUN/TURN servers of learning groups routed via the policy; routed outside sessions too
	KindDrop    = "x" // addresses answered for drop: domain rules (connections rejected)
	KindDropNet = "z" // drop:asn: and drop:cidr: ranges (connections rejected)
)

// SetPrefix is shared by every ipset snake owns.
const SetPrefix = "SNK_"

// DoH set names (global).
const (
	DoHSet4 = "SNK_DOH4"
	DoHSet6 = "SNK_DOH6"
)

// SetName returns the ipset name for a policy set.
func SetName(id int, kind string, v6 bool) string {
	fam := "4"
	if v6 {
		fam = "6"
	}
	return fmt.Sprintf("%s%d_%s%s", SetPrefix, id, kind, fam)
}

// Chain names.
const (
	ChainMain   = "SNAKE"
	ChainSave   = "SNAKE_SAVE"
	ChainWAN    = "SNAKE_WAN"
	ChainRTC    = "SNAKE_RTC"
	ChainMSS    = "SNAKE_MSS"
	ChainDNS    = "SNAKE_DNS"
	ChainSNI    = "SNAKE_SNI" // nat: HTTPS -> SNI proxy (jumped to from SNAKE_DNS)
	ChainNAT    = "SNAKE_NAT"
	ChainFwd    = "SNAKE_FWD"
	ChainDNSOut = "SNAKE_DNSO" // mangle OUTPUT: dnsmasq answers -> DNS inspector
	chainPolicy = "SNAKE_P"
	chainMark   = "SNAKE_M"
)

// PolicyChain is the per-policy match chain.
func PolicyChain(id int) string { return fmt.Sprintf("%s%d", chainPolicy, id) }

// MarkChain is the per-policy mark chain.
func MarkChain(id int) string { return fmt.Sprintf("%s%d", chainMark, id) }

// ProbePref is the ip rule priority of a tunnel's probe rule.
func ProbePref(idx, merlin int) int {
	if idx <= merlin {
		return ProbePrefBase + idx
	}
	return ProbePrefExtra + idx - merlin
}

// Routing constants.
const (
	PolicyTableBase = 1000 // table = base + policy id
	ProbeTableBase  = 1300 // table = base + tunnel index
	DNSRulePrefBase = 5000 // pref = base + policy id
	ProbePrefBase   = 4980 // pref = base + tunnel index (firmware clients)
	PolicyPrefBase  = 5200 // pref = base + policy id
	// ProbePrefExtra is the base for snake's own WireGuard tunnels (tunnel
	// index 11 and up): 4980+11 would collide with the DNS rules.
	ProbePrefExtra = 5400 // pref = base + tunnel index - 10
	PrefMin        = 4980
	PrefMax        = 5499
)

// DefaultDoHDomains are well-known DNS-over-HTTPS endpoints. Their resolved
// addresses are added to the DoH sets by dnsmasq.
var DefaultDoHDomains = []string{
	"dns.google", "dns.google.com", "8888.google", "cloudflare-dns.com",
	"mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com", "one.one.one.one",
	"1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"doh.opendns.com", "doh.familyshield.opendns.com", "dns.adguard.com", "dns.adguard-dns.com",
	"dns-family.adguard.com", "unfiltered.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org",
	"doh.dns.sb", "dns.controld.com", "freedns.controld.com", "doh.mullvad.net", "dns.mullvad.net",
	"dns.alidns.com", "doh.pub", "doh.360.cn", "doh.libredns.gr", "dns.digitale-gesellschaft.ch",
	"dns.switch.ch", "doh.applied-privacy.net", "dns.brahma.world", "ordns.he.net",
}

// DefaultDoHIPs are anycast resolver addresses that answer DoH/DoQ directly by IP.
var DefaultDoHIPs = []string{
	"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
	"8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10",
	"9.9.9.11", "149.112.112.11", "94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141",
	"208.67.222.222", "208.67.220.220", "45.90.28.0/24", "45.90.30.0/24", "185.228.168.168",
	"185.228.169.168", "76.76.2.0/24", "76.76.10.0/24", "194.242.2.2", "185.222.222.222", "45.11.45.11",
}

// DefaultDoHIPv6 are IPv6 resolver addresses.
var DefaultDoHIPv6 = []string{
	"2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
	"2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9", "2620:fe::11",
	"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2620:119:35::35", "2620:119:53::53",
	"2a07:a8c0::/32", "2a07:a8c1::/32", "2a0d:2a00:1::", "2a07:e340::2",
}

// CanaryDomains make browsers/OSes disable their built-in encrypted DNS or
// relays when answered with NXDOMAIN.
var CanaryDomains = []string{
	"use-application-dns.net", // Firefox DoH canary
	"mask.icloud.com",         // iCloud Private Relay
	"mask-h2.icloud.com",
	"mask-api.icloud.com",
}

// PrivateV4 are destinations never routed by policy.
var PrivateV4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
}

// PrivateV6 are IPv6 destinations never routed by policy.
var PrivateV6 = []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
