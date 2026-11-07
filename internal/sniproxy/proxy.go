// Package sniproxy is a transparent TLS proxy that routes connections by
// their TLS server name (SNI) instead of by DNS answers.
//
// Domain rules normally work by watching the router's DNS answers. A device
// using DNS over HTTPS or DNS over TLS hides those lookups, so its
// connections to policy domains go via WAN. With SNI sniffing, iptables
// REDIRECTs new TCP 443 connections that no policy claimed (from the
// policy's devices) to this proxy. It reads the ClientHello, which carries
// the server name in clear text, matches it against the domain rules and
// dials the original destination itself with the matching policy's fwmark,
// so the router's ip rules send it through that policy's tunnel (or the
// kill switch, or WAN). Unmatched connections are dialled without a mark
// and leave via WAN as before.
//
// Nothing is decrypted: the bytes are relayed unchanged, and the client
// still verifies the real server's certificate.
//
// With Encrypted Client Hello (ECH) the real server name is encrypted; only
// the outer, public name (e.g. cloudflare-ech.com) is visible. Each policy
// chooses what happens to its clients' ECH connections (Policy.ECH):
//   - drop: reset, so its drop: rules cannot be bypassed by hiding the name
//     (one such policy for the client is enough);
//   - relay: routed by the public name like any other connection: a rule
//     for it sends them through the policy's tunnel;
//   - passthrough: the policy ignores them; with no relay policy matching,
//     they go via WAN untouched.
package sniproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/match"
)

// Policy is one policy's view for the proxy.
type Policy struct {
	ID   int
	Name string
	Set  *match.Set
	// MACs and Nets limit the policy to these clients (both empty: every
	// client). VPN server clients have no MAC address at the router and
	// are matched by address.
	MACs map[string]bool
	Nets []netip.Prefix
	// ExcludeMACs and ExcludeNets are clients the policy never applies to.
	ExcludeMACs map[string]bool
	ExcludeNets []netip.Prefix
	Mark        uint32 // fwmark of the policy's routing table
	// Set4/Set6 learn the destination of a matched connection (the
	// policy's domain sets), so later connections to it take the kernel
	// path. "" skips a family.
	Set4, Set6 string
	// DropSet4/6 learn destinations of connections that match drop: rules.
	DropSet4, DropSet6 string
	// Session4/6 are the policy's WebRTC session sets: a matched
	// connection opens the client's session window, like a connection to a
	// learned destination does.
	Session4, Session6 string
	// ECH is what happens to the policy's clients' Encrypted Client Hello
	// connections: ECHDrop, ECHRelay ("" = relay) or ECHPassthrough.
	ECH string
}

// ECH modes (config.ECHDrop, ... ; repeated to keep the package standalone).
const (
	ECHDrop        = "drop"
	ECHRelay       = "relay"
	ECHPassthrough = "passthrough"
)

// Config is the proxy's desired state.
type Config struct {
	Port     int      // listening port (all addresses; only REDIRECTed connections are served)
	IPv6     bool     // also listen on IPv6
	Policies []Policy // in policy order: the first match wins
}

// SetAdder adds addresses to ipsets (netfilter.IPSet).
type SetAdder interface {
	AddMany(name string, entries []string) error
}

// Stats are the proxy's counters.
type Stats struct {
	Listen     string         `json:"listen"`
	Active     int64          `json:"active"`
	Conns      uint64         `json:"conns"`
	Matched    uint64         `json:"matched"`
	Dropped    uint64         `json:"dropped"`     // matched a drop: rule
	NoSNI      uint64         `json:"no_sni"`      // not TLS or no server name: sent via WAN
	ECH        uint64         `json:"ech"`         // Encrypted Client Hello connections seen
	ECHRefused uint64         `json:"ech_refused"` // ECH connections reset (a policy has ech: drop)
	ECHPassed  uint64         `json:"ech_passed"`  // ECH connections relayed untouched (ech: passthrough)
	Errors     uint64         `json:"errors"`      // upstream dial failures
	Refused    uint64         `json:"refused"`     // over the connection limit, or not redirected
	ByPolicy   map[int]uint64 `json:"by_policy,omitempty"`
	LastError  string         `json:"last_error,omitempty"`
	LastErrAt  time.Time      `json:"last_error_at,omitempty"`
}

// Tunables (variables so tests can shorten them).
var (
	// helloTimeout is how long a client may take to send its ClientHello.
	// A protocol where the server speaks first sends nothing; it is then
	// relayed via WAN.
	helloTimeout = 5 * time.Second
	dialTimeout  = 10 * time.Second
	// learnTTL skips re-adding a destination learned recently.
	learnTTL = 5 * time.Minute
	// maxConns bounds concurrent proxied connections.
	maxConns int64 = 4096
)

// Proxy is the running proxy. The zero value is stopped.
type Proxy struct {
	Sets SetAdder

	// Test hooks.
	origDst func(*net.TCPConn) (netip.AddrPort, error)
	dial    func(ctx context.Context, mark uint32, addr string) (net.Conn, error)

	mu    sync.Mutex
	cfg   Config
	lns   []net.Listener
	neigh neighbors
	pol   atomic.Pointer[[]Policy]

	learnMu sync.Mutex
	learned map[string]time.Time

	active  atomic.Int64
	conns   atomic.Uint64
	matched atomic.Uint64
	dropped atomic.Uint64
	noSNI   atomic.Uint64
	ech     atomic.Uint64
	echRef  atomic.Uint64
	echPass atomic.Uint64
	errs    atomic.Uint64
	refused atomic.Uint64
	statMu  sync.Mutex
	byPol   map[int]uint64
	lastErr string
	lastAt  time.Time
}

// Running reports whether the proxy is listening.
func (p *Proxy) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.lns) > 0
}

// Configure starts, reconfigures or (with no policies) stops the proxy.
// Policy changes take effect for new connections without restarting the
// listeners.
func (p *Proxy) Configure(c Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	pols := append([]Policy(nil), c.Policies...)
	p.pol.Store(&pols)
	if len(pols) == 0 {
		p.closeLocked()
		p.cfg = c
		return nil
	}
	if len(p.lns) > 0 && c.Port == p.cfg.Port && c.IPv6 == p.cfg.IPv6 {
		p.cfg = c
		return nil
	}
	p.closeLocked()
	p.cfg = c
	port := strconv.Itoa(c.Port)
	ln, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", port))
	if err != nil {
		return fmt.Errorf("sni proxy: %w", err)
	}
	p.lns = append(p.lns, ln)
	if c.IPv6 {
		if ln6, err := net.Listen("tcp6", net.JoinHostPort("::", port)); err == nil {
			p.lns = append(p.lns, ln6)
		} else {
			logx.Warnf("sni proxy: IPv6 listener: %v", err)
		}
	}
	for _, ln := range p.lns {
		go p.serve(ln)
	}
	logx.Infof("sni proxy listening on port %d", c.Port)
	return nil
}

func (p *Proxy) closeLocked() {
	for _, ln := range p.lns {
		_ = ln.Close()
	}
	if len(p.lns) > 0 {
		logx.Infof("sni proxy stopped")
	}
	p.lns = nil
}

// Stop closes the listeners. Relayed connections keep running.
func (p *Proxy) Stop() { _ = p.Configure(Config{}) }

// Addr is the first listener's address ("" when stopped).
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lns) == 0 {
		return ""
	}
	return p.lns[0].Addr().String()
}

// Stats returns a snapshot of the counters.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	listen := ""
	if len(p.lns) > 0 {
		listen = ":" + strconv.Itoa(p.cfg.Port)
	}
	p.mu.Unlock()
	s := Stats{
		Listen: listen, Active: p.active.Load(), Conns: p.conns.Load(), Matched: p.matched.Load(),
		Dropped: p.dropped.Load(), NoSNI: p.noSNI.Load(), ECH: p.ech.Load(), ECHRefused: p.echRef.Load(), ECHPassed: p.echPass.Load(), Errors: p.errs.Load(), Refused: p.refused.Load(),
	}
	p.statMu.Lock()
	if len(p.byPol) > 0 {
		s.ByPolicy = map[int]uint64{}
		for k, v := range p.byPol {
			s.ByPolicy[k] = v
		}
	}
	s.LastError, s.LastErrAt = p.lastErr, p.lastAt
	p.statMu.Unlock()
	return s
}

func (p *Proxy) fail(format string, a ...any) {
	p.errs.Add(1)
	msg := fmt.Sprintf(format, a...)
	logx.Debugf("sni proxy: %s", msg)
	p.statMu.Lock()
	p.lastErr, p.lastAt = msg, time.Now()
	p.statMu.Unlock()
}

func (p *Proxy) serve(ln net.Listener) {
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Out of file descriptors and the like: back off.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay < time.Second {
				delay *= 2
			}
			logx.Warnf("sni proxy: accept: %v", err)
			time.Sleep(delay)
			continue
		}
		delay = 0
		tc, ok := c.(*net.TCPConn)
		if !ok {
			_ = c.Close()
			continue
		}
		if p.active.Add(1) > maxConns {
			p.active.Add(-1)
			p.refused.Add(1)
			reset(tc)
			continue
		}
		go func() {
			defer p.active.Add(-1)
			defer func() {
				if r := recover(); r != nil {
					logx.Errorf("sni proxy: panic: %v", r)
					reset(tc)
				}
			}()
			p.handle(tc)
		}()
	}
}

// reset closes a connection with a TCP RST, so the client fails fast.
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

// match finds the first policy whose rules match name and that applies to
// the client.
func (p *Proxy) match(name string, client netip.Addr) (Policy, match.Result, bool) {
	return matchIn(name, p.applicable(client))
}

// matchIn finds the first of pols whose rules match name.
func matchIn(name string, pols []Policy) (Policy, match.Result, bool) {
	if name == "" {
		return Policy{}, match.Result{}, false
	}
	for _, pol := range pols {
		if res := pol.Set.MatchAny(name); res.Matched {
			return pol, res, true
		}
	}
	return Policy{}, match.Result{}, false
}

// applicable lists, in order, the policies that apply to the client.
func (p *Proxy) applicable(client netip.Addr) []Policy {
	pols := p.pol.Load()
	if pols == nil {
		return nil
	}
	mac, looked := "", false
	lookup := func() string {
		if !looked {
			mac, looked = p.neigh.mac(client), true
		}
		return mac
	}
	var out []Policy
	for _, pol := range *pols {
		if inNets(pol.ExcludeNets, client) || (len(pol.ExcludeMACs) > 0 && pol.ExcludeMACs[lookup()]) {
			continue
		}
		if len(pol.MACs)+len(pol.Nets) == 0 || inNets(pol.Nets, client) {
			out = append(out, pol)
			continue
		}
		if len(pol.MACs) == 0 {
			continue
		}
		if pol.MACs[lookup()] {
			out = append(out, pol)
		}
	}
	return out
}

func inNets(nets []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// echPolicies splits the policies applying to the client by ECH mode: a
// policy that drops ECH (first one), the policies that route ECH by the
// public name, and whether any passes it through.
func (p *Proxy) echPolicies(client netip.Addr) (drop *Policy, relay []Policy, passthrough bool) {
	for _, pol := range p.applicable(client) {
		switch pol.ECH {
		case ECHDrop:
			if drop == nil {
				pol := pol
				drop = &pol
			}
		case ECHPassthrough:
			passthrough = true
		default:
			relay = append(relay, pol)
		}
	}
	return drop, relay, passthrough
}

func (p *Proxy) handle(c *net.TCPConn) {
	p.conns.Add(1)
	od := p.origDst
	if od == nil {
		od = originalDst
	}
	dst, err := od(c)
	local, _ := c.LocalAddr().(*net.TCPAddr)
	if err != nil || !dst.IsValid() || (local != nil && local.AddrPort().Addr().Unmap() == dst.Addr().Unmap() && int(dst.Port()) == local.Port) {
		// Not a redirected connection (someone connected to the port
		// directly): refuse, or it would loop back to itself.
		p.refused.Add(1)
		reset(c)
		return
	}
	var client netip.Addr
	if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		client = ra.AddrPort().Addr().Unmap()
	}

	buf := make([]byte, 0, 4096)
	var hello Hello
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	for {
		if len(buf) == cap(buf) {
			if cap(buf) >= maxHello {
				break
			}
			nb := make([]byte, len(buf), 2*cap(buf))
			copy(nb, buf)
			buf = nb
		}
		n, rerr := c.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		h, perr := parseHello(buf)
		if perr == nil {
			hello = h
			break
		}
		if perr != errNeedMore || rerr != nil {
			if rerr != nil && len(buf) == 0 && !isTimeout(rerr) {
				_ = c.Close() // client went away
				return
			}
			break // not TLS, timed out or closed early: relay as is
		}
	}
	_ = c.SetReadDeadline(time.Time{})

	var mark uint32
	var pol Policy
	var res match.Result
	var ok bool
	if hello.ECH {
		p.ech.Add(1)
		drop, relay, passthrough := p.echPolicies(client)
		if drop != nil {
			p.echRef.Add(1)
			logx.Debugf("sni proxy: %s -> %s (%s) refused: Encrypted Client Hello (policy %s)", client, dst, hello.ServerName, drop.Name)
			reset(c)
			return
		}
		// Routed by the outer (public) name, by the policies that relay
		// ECH; passthrough policies leave it alone.
		pol, res, ok = matchIn(hello.ServerName, relay)
		if !ok && passthrough {
			p.echPass.Add(1)
			logx.Debugf("sni proxy: %s -> %s (%s) passed through: Encrypted Client Hello", client, dst, hello.ServerName)
		}
	} else {
		pol, res, ok = p.match(hello.ServerName, client)
	}
	switch {
	case hello.ServerName == "":
		p.noSNI.Add(1)
	case ok && res.Drop:
		p.dropped.Add(1)
		p.learn(dst.Addr(), pol.DropSet4, pol.DropSet6)
		logx.Debugf("sni proxy: %s -> %s (%s) blocked by %s rule %s", client, dst, hello.ServerName, pol.Name, res.Rule)
		reset(c)
		return
	case ok:
		mark = pol.Mark
		p.matched.Add(1)
		p.statMu.Lock()
		if p.byPol == nil {
			p.byPol = map[int]uint64{}
		}
		p.byPol[pol.ID]++
		p.statMu.Unlock()
		p.learn(dst.Addr(), pol.Set4, pol.Set6)
		if client.IsValid() {
			p.learn(client, pol.Session4, pol.Session6)
		}
		logx.Debugf("sni proxy: %s -> %s (%s) via policy %s", client, dst, hello.ServerName, pol.Name)
	}
	dial := p.dial
	if dial == nil {
		dial = func(ctx context.Context, mark uint32, addr string) (net.Conn, error) {
			return markedDialer(mark, dialTimeout).DialContext(ctx, "tcp", addr)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	up, err := dial(ctx, mark, dst.String())
	cancel()
	if err != nil {
		who := "WAN"
		if ok {
			who = "policy " + pol.Name
		}
		p.fail("%s (%s) via %s: %v", dst, hello.ServerName, who, err)
		reset(c)
		return
	}
	if len(buf) > 0 {
		if _, err := up.Write(buf); err != nil {
			_ = up.Close()
			reset(c)
			return
		}
	}
	relay(c, up)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// relay copies both ways until both directions finish. Between two TCP
// connections io.Copy uses splice(2), so data does not pass through user
// space buffers.
func relay(a *net.TCPConn, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	_, _ = io.Copy(a, b)
	closeWrite(a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// learn adds addr to the set of its family, at most once per learnTTL.
func (p *Proxy) learn(addr netip.Addr, set4, set6 string) {
	if p.Sets == nil || !addr.IsValid() {
		return
	}
	addr = addr.Unmap()
	set := set4
	if addr.Is6() {
		set = set6
	}
	if set == "" {
		return
	}
	key := set + " " + addr.String()
	now := time.Now()
	p.learnMu.Lock()
	if p.learned == nil {
		p.learned = map[string]time.Time{}
	}
	if t, ok := p.learned[key]; ok && now.Sub(t) < learnTTL {
		p.learnMu.Unlock()
		return
	}
	p.learned[key] = now
	if len(p.learned) > 8192 {
		for k, t := range p.learned {
			if now.Sub(t) >= learnTTL {
				delete(p.learned, k)
			}
		}
	}
	p.learnMu.Unlock()
	if err := p.Sets.AddMany(set, []string{addr.String()}); err != nil {
		logx.Debugf("sni proxy: add %s to %s: %v", addr, set, err)
		p.learnMu.Lock()
		delete(p.learned, key)
		p.learnMu.Unlock()
	}
}

// PolicyIDs lists the configured policy ids (for status).
func (p *Proxy) PolicyIDs() []int {
	pols := p.pol.Load()
	if pols == nil {
		return nil
	}
	out := make([]int, 0, len(*pols))
	for _, x := range *pols {
		out = append(out, x.ID)
	}
	sort.Ints(out)
	return out
}
