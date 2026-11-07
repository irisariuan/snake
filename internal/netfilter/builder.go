package netfilter

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/irisariuan/snake/internal/config"
)

// IPv6 effective modes.
const (
	V6Route = "route" // mark + route via tunnel
	V6Block = "block" // mark + reject
	V6Off   = "off"   // untouched
)

// WebRTC effective modes.
const (
	RTCQueue = "queue" // NFQUEUE STUN learning
	RTCPorts = "ports" // fallback: STUN/TURN ports during session window
	RTCOff   = "off"
)

// PolicyState is a policy plus its runtime decisions.
type PolicyState struct {
	Policy config.Policy
	// Clients are the policy's devices, groups expanded: MAC addresses,
	// IP addresses or subnets. Empty: every client (destination policy).
	Clients []string
	// Excluded are devices the policy never handles (groups expanded):
	// they return from its chains before anything matches.
	Excluded     []string
	ActiveTunnel string // "" when no tunnel is usable
	IPv6Mode     string // V6Route / V6Block / V6Off
	WebRTCMode   string // RTCQueue / RTCPorts / RTCOff
	Drops        bool   // the policy has drop: rules
}

// Options describe router capabilities and existing state.
type Options struct {
	IPv6    bool
	IPv6NAT bool
	// DNSQueue > 0 sends dnsmasq's UDP answers to LAN clients (and to the
	// router itself) through the DNS inspector queue.
	DNSQueue int
	// Existing chain names per "family/table" key (e.g. "4/mangle"); chains
	// that are no longer generated get deleted.
	Existing map[string][]string
	// TunnelAddrs are the addresses of each tunnel interface (both
	// families). Connections NATed out a tunnel have its address as reply
	// destination, which identifies them even when their conntrack mark is
	// lost.
	TunnelAddrs map[string][]string
	// WANAddrs identify connections already NATed onto WAN. Firmware can
	// overwrite their conntrack mark with a value that resembles a policy.
	WANAddrs []string
	// SNIPort > 0 is the port of the running SNI proxy: new TCP 443
	// connections of sniffing policies' clients that no policy claimed are
	// redirected to it. 0 installs no redirect (proxy not running).
	SNIPort int
	// LANAddr is the router's LAN IPv4 address. DNS hijacking on routed
	// client interfaces (VPN servers) DNATs to it: dnsmasq may not listen
	// on those interfaces' own addresses.
	LANAddr string
}

// Plan is a set of iptables-restore payloads keyed by "family/table".
type Plan struct {
	Restore map[string]string
	// Hooks are the jumps from built-in chains to snake chains.
	Hooks []Hook
}

// Hook is a jump from a built-in chain.
type Hook struct {
	V6    bool
	Table string
	Chain string
	Args  []string
}

// Tables is the ordered list of family/table keys.
var Tables = []string{"4/mangle", "4/nat", "4/filter", "6/mangle", "6/nat", "6/filter"}

type table struct {
	chains []string
	seen   map[string]bool
	rules  []string
}

func (t *table) chain(name string) {
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	if !t.seen[name] {
		t.seen[name] = true
		t.chains = append(t.chains, name)
	}
}

func (t *table) add(chain string, args ...string) {
	t.rules = append(t.rules, "-A "+chain+" "+strings.Join(args, " "))
}

func (t *table) render(name string, existing []string) string {
	var b strings.Builder
	b.WriteString("*" + name + "\n")
	for _, c := range t.chains {
		b.WriteString(":" + c + " - [0:0]\n")
	}
	var stale []string
	for _, c := range existing {
		if !t.seen[c] {
			// Declaring flushes it under --noflush; then delete it.
			b.WriteString(":" + c + " - [0:0]\n")
			stale = append(stale, c)
		}
	}
	for _, r := range t.rules {
		b.WriteString(r + "\n")
	}
	sort.Strings(stale)
	for _, c := range stale {
		b.WriteString("-X " + c + "\n")
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func hex(v uint32) string { return fmt.Sprintf("0x%x", v) }

// Build generates the complete ruleset for all enabled policies.
func Build(s config.Settings, states []PolicyState, opt Options) Plan {
	plan := Plan{Restore: map[string]string{}}
	families := []bool{false}
	if opt.IPv6 {
		families = append(families, true)
	}
	for _, v6 := range families {
		fam := "4"
		if v6 {
			fam = "6"
		}
		mangle, nat, filter := buildFamily(s, states, v6, opt)
		plan.Restore[fam+"/mangle"] = mangle.render("mangle", opt.Existing[fam+"/mangle"])
		plan.Restore[fam+"/filter"] = filter.render("filter", opt.Existing[fam+"/filter"])
		if !v6 || opt.IPv6NAT {
			plan.Restore[fam+"/nat"] = nat.render("nat", opt.Existing[fam+"/nat"])
		}
		for _, lan := range s.ClientInterfaces() {
			plan.Hooks = append(plan.Hooks, Hook{V6: v6, Table: "mangle", Chain: "PREROUTING", Args: []string{"-i", lan, "-j", ChainMain}})
		}
		plan.Hooks = append(plan.Hooks,
			Hook{V6: v6, Table: "mangle", Chain: "FORWARD", Args: []string{"-j", ChainMSS}},
			Hook{V6: v6, Table: "mangle", Chain: "OUTPUT", Args: []string{"-p", "udp", "--sport", "53", "-j", ChainDNSOut}},
			Hook{V6: v6, Table: "filter", Chain: "FORWARD", Args: []string{"-j", ChainFwd}},
		)
		if !v6 || opt.IPv6NAT {
			for _, lan := range s.ClientInterfaces() {
				plan.Hooks = append(plan.Hooks, Hook{V6: v6, Table: "nat", Chain: "PREROUTING", Args: []string{"-i", lan, "-j", ChainDNS}})
			}
			plan.Hooks = append(plan.Hooks, Hook{V6: v6, Table: "nat", Chain: "POSTROUTING", Args: []string{"-j", ChainNAT}})
		}
	}
	return plan
}

func buildFamily(s config.Settings, states []PolicyState, v6 bool, opt Options) (mangle, nat, filter *table) {
	mangle, nat, filter = &table{}, &table{}, &table{}
	mask := hex(s.MarkMask)
	rmask := hex(s.RouteMask())
	cmask := hex(s.ConnMarkMask)
	qdir := hex(config.QoSDirMask)
	lans := s.ClientInterfaces()
	for _, c := range []string{ChainMain, ChainSave, ChainRTC, ChainMSS, ChainDNSOut} {
		mangle.chain(c)
	}
	if opt.DNSQueue > 0 {
		q := fmt.Sprint(opt.DNSQueue)
		for _, lan := range lans {
			mangle.add(ChainDNSOut, "-o", lan, "-j NFQUEUE --queue-num", q, "--queue-bypass")
		}
		mangle.add(ChainDNSOut, "-o lo -j NFQUEUE --queue-num", q, "--queue-bypass")
	}
	nat.chain(ChainDNS)
	nat.chain(ChainNAT)
	filter.chain(ChainFwd)

	private := PrivateV4
	reject := "icmp-port-unreachable"
	if v6 {
		private = PrivateV6
		reject = "icmp6-port-unreachable"
	}

	// Policy ownership lives in separate conntrack bits, never in the
	// firmware's QoS category/flow-id bits. Translate explicitly below.
	// NAT identity takes precedence over shared firmware marks. A WAN flow
	// can acquire a policy-looking connmark after classification, even with
	// Adaptive QoS disabled. Restoring it would move that flow into a VPN.
	// Clear only snake's packet bits; leave the firmware's connmark alone.
	for _, addr := range opt.WANAddrs {
		ip := net.ParseIP(addr)
		if ip == nil || ip.IsUnspecified() || (ip.To4() == nil) != v6 {
			continue
		}
		mangle.chain(ChainWAN)
		mangle.add(ChainMain, "-m conntrack --ctstate ESTABLISHED,RELATED --ctrepldst", ip.String(), "-g", ChainWAN)
	}
	if mangle.seen[ChainWAN] {
		// A real QoS packet mark is preserved in full; RouteMask prevents
		// it from matching a VPN ip rule. Clear ambiguous policy-looking
		// packet bits only when no QoS direction is present.
		mangle.add(ChainWAN, "-m mark --mark 0/"+qdir, "-j MARK --set-xmark", "0/"+mask)
		mangle.add(ChainWAN, "-j RETURN")
	}
	// A connection NATed out a tunnel (reply destination = the tunnel's
	// address) stays in that tunnel even if its conntrack mark was lost:
	// other firmware components rewrite conntrack marks, and without this
	// such a connection fell through to the WAN rule below and timed out
	// (its packets left via WAN with the tunnel's source address).
	recovered := map[string]bool{}
	for _, st := range states {
		if !st.Policy.Enabled || st.ActiveTunnel == "" || (v6 && st.IPv6Mode != V6Route) {
			continue
		}
		ifc := config.TunnelInterface(st.ActiveTunnel)
		if recovered[ifc] {
			continue
		}
		recovered[ifc] = true
		for _, a := range opt.TunnelAddrs[ifc] {
			ip := net.ParseIP(a)
			if ip == nil || (ip.To4() == nil) != v6 {
				continue
			}
			mangle.add(ChainMain, "-m connmark --mark 0/"+cmask, "-m conntrack --ctstate ESTABLISHED,RELATED --ctrepldst", a, "-g", MarkChain(st.Policy.ID))
		}
	}
	for _, st := range states {
		if !st.Policy.Enabled || (v6 && st.IPv6Mode == V6Off) {
			continue
		}
		id := st.Policy.ID
		mark, conn := hex(s.PolicyMark(id)), hex(s.ConnMark(id))
		mangle.add(ChainSave, "-m mark --mark", mark+"/"+rmask, "-j CONNMARK --set-xmark", conn+"/"+cmask)
		mangle.add(ChainMain, "-m connmark --mark", conn+"/"+cmask, "-g", MarkChain(id))
		// Routing has finished at FORWARD. Reuse the existing MSS hook
		// to restore QoS classification for egress scheduling. Filter and
		// NAT policy checks use isolated connection ownership instead of
		// the now-restored QoS packet bits. Reusing the hook also keeps
		// rollback compatible with older versions' hook cleanup.
		mangle.add(ChainMSS, "-m connmark --mark", conn+"/"+cmask, "-m connmark ! --mark 0/"+qdir,
			"-j CONNMARK --restore-mark --nfmask", hex(config.AdaptiveQoSMask), "--ctmask", hex(config.AdaptiveQoSMask))
	}
	// NFQUEUE repeats a new STUN packet with an explicit policy mark.
	// QoS marks must never be saved as policy ownership.
	mangle.add(ChainMain, "-m mark ! --mark 0/"+mask, "-m mark --mark 0/"+qdir, "-g", ChainSave)
	mangle.add(ChainMain, "-d", strings.Join(private, ","), "-j RETURN")
	// A connection keeps the route it started with. One that began on WAN
	// (no policy mark) must not move into a tunnel when its destination
	// joins a policy set later (e.g. a CDN address shared with a policy
	// domain): its NAT binding is WAN's, so in the tunnel it would stall.
	// Only new connections are matched against policies; failover clears
	// the conntrack entries it needs to move. INVALID and UNTRACKED packets
	// stay on their route too: on Broadcom routers many packets of
	// accelerated WAN flows are seen that way, and matching them against
	// policies pushed some into a tunnel and slowed WAN traffic (v1.0.5).
	mangle.add(ChainMain, "-m conntrack ! --ctstate NEW -j RETURN")
	mangle.add(ChainRTC, "-m mark ! --mark 0/"+mask, "-m mark --mark 0/"+qdir, "-j RETURN")

	tunnels := map[string]bool{}
	type scope struct {
		global  bool
		clients map[string]bool
	}
	scopes := map[string]*scope{} // leak feature -> scope
	// Policies with excluded devices get their own guarded chain per
	// feature instead of joining the merged scope.
	guarded := map[string][]PolicyState{}
	addScope := func(feature string, st PolicyState) {
		if len(st.Excluded) > 0 {
			guarded[feature] = append(guarded[feature], st)
			return
		}
		sc := scopes[feature]
		if sc == nil {
			sc = &scope{clients: map[string]bool{}}
			scopes[feature] = sc
		}
		if len(st.Clients) == 0 {
			sc.global = true
		}
		for _, m := range st.Clients {
			sc.clients[m] = true
		}
	}
	// who lists the match prefixes for traffic from the given clients
	// (every client when empty) on every client interface. A device that
	// cannot be matched in this family or on an interface (an IPv4
	// address in the IPv6 table, a MAC on a routed tunnel) is skipped.
	who := func(clients []string) [][]string {
		var out [][]string
		for _, lan := range lans {
			if len(clients) == 0 {
				out = append(out, []string{"-i", lan})
				continue
			}
			for _, c := range clients {
				if m, ok := clientMatch(c, v6, config.L2Interface(lan)); ok {
					out = append(out, []string{"-i", lan, m})
				}
			}
		}
		return out
	}

	// guard starts a chain with a RETURN for each excluded device.
	guard := func(t *table, chain string, excluded []string) {
		t.chain(chain)
		for _, c := range excluded {
			if m, ok := clientMatch(c, v6, true); ok {
				t.add(chain, m, "-j RETURN")
			}
		}
	}

	for _, st := range states {
		p := st.Policy
		if !p.Enabled {
			continue
		}
		// drop: rules reject connections from the policy's devices (the
		// whole LAN for destination-only policies) to the drop sets. They
		// apply on IPv6 too, whatever the policy does with IPv6 traffic.
		if st.Drops {
			into := ChainFwd
			if len(st.Excluded) > 0 {
				into = GuardChain(p.ID, "drop")
				guard(filter, into, st.Excluded)
				filter.add(ChainFwd, "-j", into)
			}
			for _, set := range []string{SetName(p.ID, KindDrop, v6), SetName(p.ID, KindDropNet, v6)} {
				for _, w := range who(st.Clients) {
					filter.add(into, append(w, "-p tcp -m set --match-set", set, "dst -j REJECT --reject-with tcp-reset")...)
					filter.add(into, append(w, "-m set --match-set", set, "dst -j REJECT --reject-with", reject)...)
				}
			}
		}
		if v6 && st.IPv6Mode == V6Off {
			continue
		}
		for _, t := range p.Tunnels {
			tunnels[config.TunnelInterface(t)] = true
		}
		id := p.ID
		mark := hex(s.PolicyMark(id))
		pc, mc := PolicyChain(id), MarkChain(id)
		mangle.chain(pc)
		mangle.chain(mc)
		mangle.add(mc, "-j MARK --set-xmark", mark+"/"+rmask)
		mangle.add(mc, "-g", ChainSave)

		dsets := []string{}
		if p.HasDomains() {
			dsets = append(dsets, SetName(id, KindDomain, v6))
		}
		if len(p.ASNs)+len(p.CIDRs) > 0 {
			dsets = append(dsets, SetName(id, KindNet, v6))
		}
		// Inside SNAKE the interface is already one of the client
		// interfaces; a MAC match simply never matches on a routed one.
		sel := clientMatches(st.Clients, v6)

		// Session refresh for WebRTC tracking: a NEW connection from a client
		// to a policy destination (re)opens that client's session window. So
		// does STUN to a server learned in an earlier session: ICE gathering
		// often starts before the first connection to a policy destination,
		// and the peers it then checks must be learned too.
		// Excluded devices leave the policy chain first; the session
		// refresh then moves into it, after them.
		refreshIn := ChainMain
		if len(st.Excluded) > 0 {
			guard(mangle, pc, st.Excluded)
			refreshIn = pc
		}
		if st.WebRTCMode != RTCOff && len(dsets) > 0 {
			sess := SetName(id, KindSession, v6)
			opens := []string{}
			for _, ds := range dsets {
				opens = append(opens, "-m conntrack --ctstate NEW -m set --match-set "+ds+" dst")
			}
			opens = append(opens, "-p udp -m conntrack --ctstate NEW -m set --match-set "+SetName(id, KindServer, v6)+" dst")
			for _, base := range opens {
				if len(st.Clients) == 0 {
					mangle.add(refreshIn, base, "-j SET --add-set", sess, "src --exist")
				}
				for _, m := range sel {
					mangle.add(refreshIn, m, base, "-j SET --add-set", sess, "src --exist")
				}
			}
		}

		mangle.add(ChainMain, "-j", pc)
		mangle.add(pc, "-m mark ! --mark 0/"+mask, "-m mark --mark 0/"+qdir, "-j RETURN")
		switch {
		case len(st.Clients) > 0 && len(dsets) == 0: // whole device
			for _, m := range sel {
				mangle.add(pc, m, "-g", mc)
			}
		case len(st.Clients) > 0: // device + destination
			for _, m := range sel {
				for _, ds := range dsets {
					mangle.add(pc, m, "-m set --match-set", ds, "dst -g", mc)
				}
			}
		default: // destination only
			for _, ds := range dsets {
				mangle.add(pc, "-m set --match-set", ds, "dst -g", mc)
			}
		}

		// WebRTC: learned peers are routed only for clients inside a session window.
		if st.WebRTCMode != RTCOff && len(dsets) > 0 {
			sess := SetName(id, KindSession, v6)
			peers := SetName(id, KindPeer, v6)
			mangle.add(pc, "-p udp -m set --match-set", sess, "src -m set --match-set", peers, "dst -g", mc)
			// STUN/TURN servers of learning groups routed via this policy
			// (SNK_<id>_t, kept in sync by the daemon) are routed for the
			// policy's clients even outside a session window, so binding
			// requests sent before the session opens cannot reveal the WAN
			// address.
			srv := SetName(id, KindServer, v6)
			if len(st.Clients) == 0 {
				mangle.add(pc, "-p udp -m set --match-set", srv, "dst -g", mc)
			}
			for _, m := range sel {
				mangle.add(pc, m, "-p udp -m set --match-set", srv, "dst -g", mc)
			}
			switch st.WebRTCMode {
			case RTCQueue:
				q := fmt.Sprint(s.QueueBase + id)
				mangle.add(ChainRTC, "-p udp -m conntrack --ctstate NEW -m set --match-set", sess,
					"src -j NFQUEUE --queue-num", q, "--queue-bypass")
			case RTCPorts:
				mangle.add(pc, "-p udp -m multiport --dports", s.STUNPorts, "-m set --match-set", sess, "src -g", mc)
			}
		}

		// IPv6 block: policy traffic that cannot be carried over IPv6 is rejected
		// so clients fall back to IPv4 (which goes through the tunnel).
		if v6 && st.IPv6Mode == V6Block {
			filter.add(ChainFwd, "-m connmark --mark", hex(s.ConnMark(id))+"/"+cmask, "-p tcp -j REJECT --reject-with tcp-reset")
			filter.add(ChainFwd, "-m connmark --mark", hex(s.ConnMark(id))+"/"+cmask, "-j REJECT --reject-with icmp6-adm-prohibited")
		}

		l := p.Leak
		if l.HijackDNS {
			addScope("dns", st)
		}
		if s.DoTBlocked(p) {
			addScope("dot", st)
		}
		if s.DoHBlocked(p) {
			addScope("doh", st)
		}
		if l.BlockQUIC {
			addScope("quic", st)
		}
		if p.Sniffs() {
			addScope("sni", st)
		}
	}
	mangle.add(ChainMain, "-j", ChainRTC)

	// Leak protection, scoped to the devices of the policies that asked for it
	// (or the whole LAN for destination-only policies).
	scopeWho := func(feature string) [][]string {
		sc := scopes[feature]
		if sc == nil {
			return nil
		}
		if sc.global {
			return who(nil)
		}
		clients := make([]string, 0, len(sc.clients))
		for m := range sc.clients {
			clients = append(clients, m)
		}
		sort.Strings(clients)
		return who(clients)
	}
	// emit adds a feature's rules: gen writes them into a chain for a set
	// of match prefixes. The merged scope goes straight into parent; each
	// policy with excluded devices gets a chain of its own, which returns
	// for those devices first and is jumped to from parent.
	emit := func(t *table, parent, feature, tag string, gen func(chain string, w [][]string)) {
		if w := scopeWho(feature); len(w) > 0 {
			gen(parent, w)
		}
		for _, st := range guarded[feature] {
			ch := GuardChain(st.Policy.ID, tag)
			guard(t, ch, st.Excluded)
			gen(ch, who(st.Clients))
			t.add(parent, "-j", ch)
		}
	}
	rules := func(t *table, args ...[]string) func(string, [][]string) {
		return func(chain string, ws [][]string) {
			for _, a := range args {
				for _, w := range ws {
					t.add(chain, append(append([]string(nil), w...), a...)...)
				}
			}
		}
	}
	// Router-wide overrides from Settings (block_dot / block_doh).
	for feature, mode := range map[string]string{"dot": s.BlockDoT, "doh": s.BlockDoH} {
		switch mode {
		case config.BlockAlways:
			scopes[feature] = &scope{global: true, clients: map[string]bool{}}
			delete(guarded, feature)
		case config.BlockNever:
			delete(scopes, feature)
			delete(guarded, feature)
		}
	}
	// DNS hijack: REDIRECT to dnsmasq on bridges. Routed client interfaces
	// (VPN servers) DNAT to the LAN address instead, where dnsmasq always
	// listens (IPv4 only; their IPv6 DNS is left alone).
	emit(nat, ChainDNS, "dns", "dns", func(chain string, ws [][]string) {
		for _, w := range ws {
			target := "-j REDIRECT --to-ports 53"
			if !config.L2Interface(w[1]) {
				if v6 || opt.LANAddr == "" {
					continue
				}
				target = "-j DNAT --to-destination " + opt.LANAddr + ":53"
			}
			for _, proto := range []string{"udp", "tcp"} {
				nat.add(chain, append(append([]string(nil), w...), "-p", proto, "--dport 53", target)...)
			}
		}
	})
	emit(filter, ChainFwd, "dot", "dot", rules(filter,
		[]string{"-p tcp --dport 853 -j REJECT --reject-with tcp-reset"},
		[]string{"-p udp --dport 853 -j REJECT --reject-with", reject}))
	doh := DoHSet4
	if v6 {
		doh = DoHSet6
	}
	emit(filter, ChainFwd, "doh", "doh", rules(filter,
		[]string{"-p tcp --dport 443 -m set --match-set", doh, "dst -j REJECT --reject-with tcp-reset"},
		[]string{"-p udp --dport 443 -m set --match-set", doh, "dst -j REJECT --reject-with", reject}))
	emit(filter, ChainFwd, "quic", "quic", rules(filter, []string{"-p udp --dport 443 -j REJECT --reject-with", reject}))

	// SNI sniffing: HTTPS connections no policy claimed go to the proxy,
	// which routes them by TLS server name. Only families with NAT can be
	// redirected.
	if opt.SNIPort > 0 && (scopes["sni"] != nil || len(guarded["sni"]) > 0) && (!v6 || opt.IPv6NAT) {
		nat.chain(ChainSNI)
		emit(nat, ChainDNS, "sni", "sni", rules(nat, []string{"-p tcp --dport 443 -j", ChainSNI}))
		// Claimed by a policy (sets, devices, WebRTC): the kernel routes it.
		nat.add(ChainSNI, "-m connmark ! --mark 0/"+cmask, "-j RETURN")
		nat.add(ChainSNI, "-d", strings.Join(private, ","), "-j RETURN")
		// DoH resolvers and drop sets keep their filter verdicts, which a
		// redirected connection (now addressed to the router) would skip.
		nat.add(ChainSNI, "-m set --match-set", doh, "dst -j RETURN")
		for _, st := range states {
			if st.Policy.Enabled && st.Drops {
				for _, k := range []string{KindDrop, KindDropNet} {
					nat.add(ChainSNI, "-m set --match-set", SetName(st.Policy.ID, k, v6), "dst -j RETURN")
				}
			}
		}
		nat.add(ChainSNI, "-p tcp -j REDIRECT --to-ports", fmt.Sprint(opt.SNIPort))
		// QUIC carries its server name in an encrypted Initial packet the
		// proxy does not handle: unclaimed QUIC is rejected so browsers
		// fall back to TCP, which is sniffed. QUIC to policy destinations
		// (connmark set) still goes through the tunnel.
		emit(filter, ChainFwd, "sni", "sniq", rules(filter, []string{"-p udp --dport 443 -m connmark --mark 0/" + cmask, "-j REJECT --reject-with", reject}))
	}

	ifaces := make([]string, 0, len(tunnels))
	for t := range tunnels {
		ifaces = append(ifaces, t)
	}
	sort.Strings(ifaces)
	for _, ifc := range ifaces {
		mangle.add(ChainMSS, "-o", ifc, "-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
		for _, st := range states {
			if st.Policy.Enabled && (!v6 || st.IPv6Mode != V6Off) {
				nat.add(ChainNAT, "-o", ifc, "-m connmark --mark", hex(s.ConnMark(st.Policy.ID))+"/"+cmask, "-j MASQUERADE")
				// A firmware POSTROUTING hook may erase the entire
				// connmark before first-packet NAT. The routing mark is
				// still usable when no QoS direction bits are present.
				nat.add(ChainNAT, "-o", ifc, "-m mark --mark", hex(s.PolicyMark(st.Policy.ID))+"/"+rmask, "-j MASQUERADE")
				for _, lan := range lans {
					filter.add(ChainFwd, "-i", lan, "-o", ifc, "-m connmark --mark", hex(s.ConnMark(st.Policy.ID))+"/"+cmask, "-j ACCEPT")
				}
			}
		}
		for _, lan := range lans {
			filter.add(ChainFwd, "-i", ifc, "-o", lan, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
		}
	}
	return mangle, nat, filter
}

// clientMatch is the iptables match for one device entry in a family: a
// MAC address (on Ethernet interfaces only), or a source address or
// subnet of that family.
func clientMatch(client string, v6, l2 bool) (string, bool) {
	if config.ClientMAC(client) {
		return "-m mac --mac-source " + client, l2
	}
	if p, err := netip.ParsePrefix(client); err == nil {
		if p.Addr().Is6() != v6 {
			return "", false
		}
		return "-s " + p.String(), true
	}
	if a, err := netip.ParseAddr(client); err == nil {
		if a.Is6() != v6 {
			return "", false
		}
		return "-s " + a.String(), true
	}
	return "", false
}

// clientMatches lists the matches of the devices usable in a family.
func clientMatches(clients []string, v6 bool) []string {
	var out []string
	for _, c := range clients {
		if m, ok := clientMatch(c, v6, true); ok {
			out = append(out, m)
		}
	}
	return out
}
