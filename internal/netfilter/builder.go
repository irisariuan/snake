package netfilter

import (
	"fmt"
	"net"
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
	Policy       config.Policy
	MACs         []string // resolved device MACs (groups expanded)
	ActiveTunnel string   // "" when no tunnel is usable
	IPv6Mode     string   // V6Route / V6Block / V6Off
	WebRTCMode   string   // RTCQueue / RTCPorts / RTCOff
	Drops        bool     // the policy has drop: rules
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
		lan := s.LANInterfaces
		plan.Hooks = append(plan.Hooks,
			Hook{V6: v6, Table: "mangle", Chain: "PREROUTING", Args: []string{"-i", lan, "-j", ChainMain}},
			Hook{V6: v6, Table: "mangle", Chain: "FORWARD", Args: []string{"-j", ChainMSS}},
			Hook{V6: v6, Table: "mangle", Chain: "OUTPUT", Args: []string{"-p", "udp", "--sport", "53", "-j", ChainDNSOut}},
			Hook{V6: v6, Table: "filter", Chain: "FORWARD", Args: []string{"-j", ChainFwd}},
		)
		if !v6 || opt.IPv6NAT {
			plan.Hooks = append(plan.Hooks,
				Hook{V6: v6, Table: "nat", Chain: "PREROUTING", Args: []string{"-i", lan, "-j", ChainDNS}},
				Hook{V6: v6, Table: "nat", Chain: "POSTROUTING", Args: []string{"-j", ChainNAT}},
			)
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
	lan := s.LANInterfaces
	for _, c := range []string{ChainMain, ChainSave, ChainRTC, ChainMSS, ChainDNSOut} {
		mangle.chain(c)
	}
	if opt.DNSQueue > 0 {
		q := fmt.Sprint(opt.DNSQueue)
		mangle.add(ChainDNSOut, "-o", lan, "-j NFQUEUE --queue-num", q, "--queue-bypass")
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
		global bool
		macs   map[string]bool
	}
	scopes := map[string]*scope{} // leak feature -> scope
	addScope := func(feature string, st PolicyState) {
		sc := scopes[feature]
		if sc == nil {
			sc = &scope{macs: map[string]bool{}}
			scopes[feature] = sc
		}
		if len(st.MACs) == 0 {
			sc.global = true
		}
		for _, m := range st.MACs {
			sc.macs[m] = true
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
			who := [][]string{{"-i", lan}}
			if len(st.MACs) > 0 {
				who = nil
				for _, m := range st.MACs {
					who = append(who, []string{"-i", lan, "-m mac --mac-source", m})
				}
			}
			for _, set := range []string{SetName(p.ID, KindDrop, v6), SetName(p.ID, KindDropNet, v6)} {
				for _, w := range who {
					filter.add(ChainFwd, append(w, "-p tcp -m set --match-set", set, "dst -j REJECT --reject-with tcp-reset")...)
					filter.add(ChainFwd, append(w, "-m set --match-set", set, "dst -j REJECT --reject-with", reject)...)
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
		macMatch := func(m string) string { return "-m mac --mac-source " + m }

		// Session refresh for WebRTC tracking: a NEW connection from a client
		// to a policy destination (re)opens that client's session window. So
		// does STUN to a server learned in an earlier session: ICE gathering
		// often starts before the first connection to a policy destination,
		// and the peers it then checks must be learned too.
		if st.WebRTCMode != RTCOff && len(dsets) > 0 {
			sess := SetName(id, KindSession, v6)
			opens := []string{}
			for _, ds := range dsets {
				opens = append(opens, "-m conntrack --ctstate NEW -m set --match-set "+ds+" dst")
			}
			opens = append(opens, "-p udp -m conntrack --ctstate NEW -m set --match-set "+SetName(id, KindServer, v6)+" dst")
			for _, base := range opens {
				if len(st.MACs) == 0 {
					mangle.add(ChainMain, base, "-j SET --add-set", sess, "src --exist")
				}
				for _, m := range st.MACs {
					mangle.add(ChainMain, macMatch(m), base, "-j SET --add-set", sess, "src --exist")
				}
			}
		}

		mangle.add(ChainMain, "-j", pc)
		mangle.add(pc, "-m mark ! --mark 0/"+mask, "-m mark --mark 0/"+qdir, "-j RETURN")
		switch {
		case len(st.MACs) > 0 && len(dsets) == 0: // whole device
			for _, m := range st.MACs {
				mangle.add(pc, macMatch(m), "-g", mc)
			}
		case len(st.MACs) > 0: // device + destination
			for _, m := range st.MACs {
				for _, ds := range dsets {
					mangle.add(pc, macMatch(m), "-m set --match-set", ds, "dst -g", mc)
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
			if len(st.MACs) == 0 {
				mangle.add(pc, "-p udp -m set --match-set", srv, "dst -g", mc)
			}
			for _, m := range st.MACs {
				mangle.add(pc, macMatch(m), "-p udp -m set --match-set", srv, "dst -g", mc)
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
	}
	mangle.add(ChainMain, "-j", ChainRTC)

	// Leak protection, scoped to the devices of the policies that asked for it
	// (or the whole LAN for destination-only policies).
	forScope := func(t *table, chain, feature string, args ...string) {
		sc := scopes[feature]
		if sc == nil {
			return
		}
		if sc.global {
			t.add(chain, append([]string{"-i", lan}, args...)...)
			return
		}
		macs := make([]string, 0, len(sc.macs))
		for m := range sc.macs {
			macs = append(macs, m)
		}
		sort.Strings(macs)
		for _, m := range macs {
			t.add(chain, append([]string{"-i", lan, "-m mac --mac-source", m}, args...)...)
		}
	}
	// Router-wide overrides from Settings (block_dot / block_doh).
	for feature, mode := range map[string]string{"dot": s.BlockDoT, "doh": s.BlockDoH} {
		switch mode {
		case config.BlockAlways:
			scopes[feature] = &scope{global: true, macs: map[string]bool{}}
		case config.BlockNever:
			delete(scopes, feature)
		}
	}
	forScope(nat, ChainDNS, "dns", "-p udp --dport 53 -j REDIRECT --to-ports 53")
	forScope(nat, ChainDNS, "dns", "-p tcp --dport 53 -j REDIRECT --to-ports 53")
	forScope(filter, ChainFwd, "dot", "-p tcp --dport 853 -j REJECT --reject-with tcp-reset")
	forScope(filter, ChainFwd, "dot", "-p udp --dport 853 -j REJECT --reject-with", reject)
	doh := DoHSet4
	if v6 {
		doh = DoHSet6
	}
	forScope(filter, ChainFwd, "doh", "-p tcp --dport 443 -m set --match-set", doh, "dst -j REJECT --reject-with tcp-reset")
	forScope(filter, ChainFwd, "doh", "-p udp --dport 443 -m set --match-set", doh, "dst -j REJECT --reject-with", reject)
	forScope(filter, ChainFwd, "quic", "-p udp --dport 443 -j REJECT --reject-with", reject)

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
				filter.add(ChainFwd, "-i", lan, "-o", ifc, "-m connmark --mark", hex(s.ConnMark(st.Policy.ID))+"/"+cmask, "-j ACCEPT")
			}
		}
		filter.add(ChainFwd, "-i", ifc, "-o", lan, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	}
	return mangle, nat, filter
}
