// Package netfilter builds and applies iptables/ipset state for snake.
package netfilter

import (
	"fmt"
	"strings"
)

// Set kinds.
const (
	KindDomain  = "d" // populated by dnsmasq in real time
	KindNet     = "n" // static CIDRs + ASN prefixes
	KindSession = "s" // WebRTC session window: client IPs with a live policy session
	KindPeer    = "r" // former WebRTC peer set (peers are sessions now); removed when found
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

// QUIC flow sets (global, hash:ip,port,ip): client address and port and
// server address of UDP 443 flows that had a reply recently. Their packets
// skip the QUIC queue.
const (
	QUICFlowSet4 = "SNK_QF4"
	QUICFlowSet6 = "SNK_QF6"
	// QUICFlowTimeout is how long a flow stays in the set after it was
	// added (seconds). Shorter than conntrack's UDP stream timeout, so a
	// new connection reusing the ports is queued again.
	QUICFlowTimeout = 120
)

// QUICFlowSet returns the QUIC flow set of a family.
func QUICFlowSet(v6 bool) string {
	if v6 {
		return QUICFlowSet6
	}
	return QUICFlowSet4
}

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
	ChainDNSOut = "SNAKE_DNSO" // mangle OUTPUT: dnsmasq answers (UDP and TCP) -> DNS inspector
	ChainRaw    = "SNAKE_RAW"  // raw PREROUTING: new QUIC flows -> SNI proxy's QUIC queue
	chainPolicy = "SNAKE_P"
	chainMark   = "SNAKE_M"
)

// PolicyChain is the per-policy match chain.
func PolicyChain(id int) string { return fmt.Sprintf("%s%d", chainPolicy, id) }

// DropSessionChain is a policy's drop session chain (filter): connections
// from a device to an address it looked up via a drop[...]: rule (and from
// the devices the rule shares with) are rejected.
func DropSessionChain(id int) string { return fmt.Sprintf("SNAKE_D%d", id) }

// SessionChain is a policy's session chain: one rule per device + address
// routed for that device only (session: rules, WebRTC peers).
func SessionChain(id int) string { return fmt.Sprintf("SNAKE_Q%d", id) }

// GuardChain is a policy's chain for one feature (drop, dns, dot, doh,
// quic, sni, sniq) when it excludes devices: it returns for them first.
func GuardChain(id int, feature string) string {
	return fmt.Sprintf("SNAKE_X%d_%s", id, strings.ToUpper(feature))
}

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

// PrivateV4 are destinations never routed by policy.
var PrivateV4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
}

// PrivateV6 are IPv6 destinations never routed by policy.
var PrivateV6 = []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
