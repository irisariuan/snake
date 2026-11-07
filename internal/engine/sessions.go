package engine

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/webrtc"
)

// Sessions are device + address pairs a policy routes for that device only:
//
//   - session: rules: the addresses a DNS answer gave the device that looked
//     the name up (or that the SNI proxy saw it connect to);
//   - WebRTC peers: the addresses a device's STUN revealed during its
//     session window.
//
// They are not added to the policy's sets and not saved. A session lasts
// SessionTTL after the device's last connection to the address: the
// daemon renews sessions with live connections (conntrack) on every scan,
// so a new connection within the TTL renews it, and the countdown only
// starts once the last connection closed. Each policy has a session chain
// (netfilter.SessionChain) with one rule per pair, rewritten as sessions
// start and end.

// Session sources.
const (
	SessionRule   = "rule"   // session: domain rule
	SessionWebRTC = "webrtc" // WebRTC peer learned from STUN
)

// maxSessions bounds the sessions per policy (the oldest give way).
const maxSessions = 4096

type sessionKey struct {
	Policy       int
	Client, Addr string
}

// Session is one device + address pair.
type Session struct {
	Policy  int       `json:"policy"`
	Client  string    `json:"client"`
	Addr    string    `json:"addr"`
	Source  string    `json:"source"`         // SessionRule or SessionWebRTC
	Rule    string    `json:"rule,omitempty"` // session: rule that matched
	Name    string    `json:"name,omitempty"` // DNS name or TLS server name
	Created time.Time `json:"created"`
	Seen    time.Time `json:"seen"` // last lookup, connection or refresh
	Expires time.Time `json:"expires"`
	// TTL is the rule's ttl option (0: session_ttl); OnLookup counts it
	// from the last lookup instead of the last connection.
	TTL      time.Duration `json:"ttl,omitempty"`
	OnLookup bool          `json:"onlookup,omitempty"`
	// Share: other devices the session is routed for (share= option):
	// "global", group names, devices.
	Share []string `json:"share,omitempty"`
}

func (se *Session) ttl(def time.Duration) time.Duration {
	if se.TTL > 0 {
		return se.TTL
	}
	return def
}

type sessionStore struct {
	mu sync.Mutex
	m  map[sessionKey]*Session
	// active: policies whose session chain exists, per family (from the
	// last apply). Chains of other policies are not written.
	active map[int][2]bool
}

func (s *sessionStore) init() {
	if s.m == nil {
		s.m = map[sessionKey]*Session{}
	}
}

func isV6(addr string) bool { return strings.Contains(addr, ":") }

func (e *Engine) sessionTTL() time.Duration {
	if cfg := e.runtime(); cfg != nil && cfg.Settings.SessionTTL > 0 {
		return time.Duration(cfg.Settings.SessionTTL) * time.Second
	}
	return 10 * time.Minute
}

// AddSessions starts (or renews) sessions of a policy for one device. New
// pairs are installed before it returns, so the caller can release the
// DNS answer or connection knowing the route is in place.
func (e *Engine) AddSessions(policy int, client string, addrs []string, source, rule, name string, opts match.Opts) error {
	c := net.ParseIP(client)
	if c == nil {
		return fmt.Errorf("session: bad device address %q", client)
	}
	client = c.String()
	now := time.Now()
	ttl := e.sessionTTL()
	if opts.TTL > 0 {
		ttl = opts.TTL
	}
	exp := now.Add(ttl)
	s := &e.sess
	s.mu.Lock()
	s.init()
	added := false
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || (ip.To4() == nil) != (c.To4() == nil) {
			continue // the families must match
		}
		k := sessionKey{policy, client, ip.String()}
		if se, ok := s.m[k]; ok {
			// A lookup renews every session, onlookup or not.
			se.Seen = now
			if exp.After(se.Expires) || se.OnLookup {
				se.Expires = exp
			}
			if rule != "" {
				se.Rule, se.Name, se.TTL, se.OnLookup = rule, name, opts.TTL, opts.OnLookup
				if !sameStrings(se.Share, opts.Share) {
					se.Share = append([]string(nil), opts.Share...)
					added = true // the chain changes
				}
			}
			continue
		}
		s.m[k] = &Session{Policy: policy, Client: client, Addr: k.Addr, Source: source, Rule: rule, Name: name, Created: now, Seen: now, Expires: exp,
			TTL: opts.TTL, OnLookup: opts.OnLookup, Share: append([]string(nil), opts.Share...)}
		added = true
	}
	if added {
		s.trim(policy)
	}
	s.mu.Unlock()
	if !added {
		return nil
	}
	return e.writeSessionChains(policy)
}

// trim keeps at most maxSessions per policy, dropping the soonest to expire.
func (s *sessionStore) trim(policy int) {
	var mine []*Session
	for k, se := range s.m {
		if k.Policy == policy {
			mine = append(mine, se)
		}
	}
	if len(mine) <= maxSessions {
		return
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Expires.Before(mine[j].Expires) })
	for _, se := range mine[:len(mine)-maxSessions] {
		delete(s.m, sessionKey{se.Policy, se.Client, se.Addr})
	}
}

// sessionPairs lists the rules of a policy's session chain in a family,
// in a stable order: [source match, address]. The source match is the
// device that started the session ("-s IP"), and the devices it is shared
// with ("-s IP/subnet", "-m mac --mac-source MAC", or "" for every device
// of the policy).
func (e *Engine) sessionPairs(id int, v6 bool) [][2]string {
	groups := e.groupMembers()
	s := &e.sess
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[[2]string]bool{}
	var out [][2]string
	for k, se := range s.m {
		if k.Policy != id || isV6(k.Addr) != v6 {
			continue
		}
		for _, spec := range shareSpecs(se, v6, groups) {
			pr := [2]string{spec, k.Addr}
			if !seen[pr] {
				seen[pr] = true
				out = append(out, pr)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][1]+" "+out[i][0] < out[j][1]+" "+out[j][0] })
	return out
}

// shareSpecs lists the source matches of a session's chain rules.
func shareSpecs(se *Session, v6 bool, groups map[string][]string) []string {
	specs := []string{"-s " + se.Client}
	var devices []string
	for _, sh := range se.Share {
		switch {
		case sh == match.ShareGlobal:
			return []string{""} // every device of the policy covers the rest
		case match.ShareDevice(sh):
			devices = append(devices, sh)
		default:
			devices = append(devices, groups[sh]...)
		}
	}
	for _, d := range devices {
		if hw, err := net.ParseMAC(d); err == nil && len(hw) == 6 {
			specs = append(specs, "-m mac --mac-source "+hw.String())
			continue
		}
		ip := net.ParseIP(d)
		if ip == nil {
			if pip, _, err := net.ParseCIDR(d); err == nil {
				ip = pip
			}
		}
		if ip != nil && (ip.To4() == nil) == v6 {
			specs = append(specs, "-s "+d)
		}
	}
	return specs
}

// groupMembers maps group names to their devices (current config).
func (e *Engine) groupMembers() map[string][]string {
	out := map[string][]string{}
	if cfg := e.runtime(); cfg != nil {
		for _, g := range cfg.Groups {
			out[g.Name] = g.MACs
		}
	}
	return out
}

// sharedLive reports whether a device the session is shared with (by
// address) has a live connection to its address. Devices given by MAC are
// not matched against the connection table.
func sharedLive(se *Session, srcs []string, groups map[string][]string) bool {
	var nets []string
	for _, sh := range se.Share {
		switch {
		case sh == match.ShareGlobal:
			return len(srcs) > 0
		case match.ShareDevice(sh):
			nets = append(nets, sh)
		default:
			nets = append(nets, groups[sh]...)
		}
	}
	for _, n := range nets {
		var pfx *net.IPNet
		if ip := net.ParseIP(n); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			pfx = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		} else if _, p, err := net.ParseCIDR(n); err == nil {
			pfx = p
		}
		if pfx == nil {
			continue
		}
		for _, src := range srcs {
			if ip := net.ParseIP(src); ip != nil && pfx.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Sessions lists the sessions of a policy (0: all), soonest to expire last.
func (e *Engine) Sessions(policy int) []Session {
	s := &e.sess
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for k, se := range s.m {
		if policy == 0 || k.Policy == policy {
			out = append(out, *se)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.After(out[j].Expires) })
	return out
}

// setSessionChains records which policies have a session chain (per
// family) after an apply, and forgets sessions of the others.
func (e *Engine) setSessionChains(active map[int][2]bool) {
	s := &e.sess
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	s.active = active
	for k := range s.m {
		if _, ok := active[k.Policy]; !ok {
			delete(s.m, k)
		}
	}
}

// writeSessionChains rewrites the session chains of the given policies
// (iptables-restore --noflush: declaring the chain flushes only it).
func (e *Engine) writeSessionChains(ids ...int) error {
	if e.DryRun || e.Disabled() {
		return nil
	}
	s := &e.sess
	s.mu.Lock()
	active := s.active
	s.mu.Unlock()
	var errs []string
	for _, v6 := range []bool{false, true} {
		var b strings.Builder
		n := 0
		for _, id := range ids {
			if !active[id][b2i(v6)] {
				continue
			}
			qc := netfilter.SessionChain(id)
			b.WriteString(":" + qc + " - [0:0]\n")
			for _, pr := range e.sessionPairs(id, v6) {
				src := ""
				if pr[0] != "" {
					src = pr[0] + " "
				}
				fmt.Fprintf(&b, "-A %s %s-d %s -g %s\n", qc, src, pr[1], netfilter.MarkChain(id))
			}
			n++
		}
		if n == 0 {
			continue
		}
		bin := "iptables-restore"
		if v6 {
			bin = "ip6tables-restore"
		}
		if _, err := e.R.RunInput("*mangle\n"+b.String()+"COMMIT\n", bin, "--noflush"); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		err := fmt.Errorf("sessions: %s", strings.Join(errs, "; "))
		logx.Warnf("%v", err)
		return err
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// refreshSessions renews sessions with a live connection and ends expired
// ones. conntrack is /proc/net/nf_conntrack (a reader in tests).
func (e *Engine) refreshSessions(conntrack io.Reader, now time.Time) {
	s := &e.sess
	s.mu.Lock()
	n := len(s.m)
	s.mu.Unlock()
	if n == 0 {
		return
	}
	live := map[[2]string]bool{}
	byDst := map[string][]string{}
	if conntrack != nil {
		sc := bufio.NewScanner(conntrack)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			if src, dst, ok := webrtc.LiveFlow(sc.Text()); ok {
				live[[2]string{src, dst}] = true
				byDst[dst] = append(byDst[dst], src)
			}
		}
	}
	groups := e.groupMembers()
	def := e.sessionTTL()
	changed := map[int]bool{}
	s.mu.Lock()
	for k, se := range s.m {
		if (live[[2]string{k.Client, k.Addr}] || (len(se.Share) > 0 && sharedLive(se, byDst[k.Addr], groups))) && !se.OnLookup {
			se.Seen = now
			if exp := now.Add(se.ttl(def)); exp.After(se.Expires) {
				se.Expires = exp
			}
			continue
		}
		if now.After(se.Expires) {
			delete(s.m, k)
			changed[k.Policy] = true
		}
	}
	s.mu.Unlock()
	if len(changed) == 0 {
		return
	}
	ids := make([]int, 0, len(changed))
	for id := range changed {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	_ = e.writeSessionChains(ids...)
}

// refreshSessionsNow reads the kernel's connection table.
func (e *Engine) refreshSessionsNow() {
	e.pruneCond(time.Now())
	f, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		e.refreshSessions(nil, time.Now()) // still expire
		return
	}
	defer f.Close()
	e.refreshSessions(f, time.Now())
}

// clearSessions ends every session of a policy (Flush learned).
func (e *Engine) clearSessions(policy int) {
	s := &e.sess
	s.mu.Lock()
	for k := range s.m {
		if k.Policy == policy {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
	_ = e.writeSessionChains(policy)
}
