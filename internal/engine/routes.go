package engine

import (
	"bufio"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/webrtc"
)

// Conditional rules (if:COND;then:ACTION;else:ACTION;finally:ACTION, see
// package match): the if: part's names are routed like plain rules, and
// the addresses they resolved to are remembered here per atom. When a
// device looks up a name of a branch, the condition is evaluated for that
// device from its live connections at that moment: an atom holds if the
// device has a live connection to one of the atom's addresses. The branch
// it picks starts route or drop sessions for the device.

// condAddrTTL is how long an address stays attributed to an if: atom
// after the last answer that gave it.
const condAddrTTL = 24 * time.Hour

type condKey struct {
	Policy int
	Rule   string
	Atom   int
}

type condStore struct {
	mu sync.Mutex
	m  map[condKey]map[string]time.Time // address -> last answered
}

// recordCond remembers that addrs were answered for these if: atoms.
func (e *Engine) recordCond(policy int, addrs []string, hits []match.CondHit) {
	now := time.Now()
	c := &e.cond
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[condKey]map[string]time.Time{}
	}
	for _, h := range hits {
		k := condKey{policy, h.Rule, h.Atom}
		if c.m[k] == nil {
			c.m[k] = map[string]time.Time{}
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				c.m[k][ip.String()] = now
			}
		}
	}
}

// pruneCond forgets addresses not answered for condAddrTTL.
func (e *Engine) pruneCond(now time.Time) {
	c := &e.cond
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, addrs := range c.m {
		for a, t := range addrs {
			if now.Sub(t) > condAddrTTL {
				delete(addrs, a)
			}
		}
		if len(addrs) == 0 {
			delete(c.m, k)
		}
	}
}

// conntrackTable returns the kernel's connection table: the procfs file
// when the kernel has it, otherwise the conntrack tool's extended listing
// (same line format; some kernels, e.g. Ubuntu's, have no procfs file).
func (e *Engine) conntrackTable() (io.ReadCloser, bool) {
	path := e.conntrackPath
	if path == "" {
		path = "/proc/net/nf_conntrack"
	}
	if f, err := os.Open(path); err == nil {
		return f, true
	}
	var b strings.Builder
	ok := false
	for _, fam := range []string{"ipv4", "ipv6"} {
		if out, err := e.R.Run("conntrack", "-L", "-o", "extended", "-f", fam); err == nil {
			b.WriteString(out + "\n")
			ok = true
		}
	}
	return io.NopCloser(strings.NewReader(b.String())), ok
}

// liveDsts lists the destinations the device has live connections to.
func (e *Engine) liveDsts(client string) map[string]bool {
	out := map[string]bool{}
	f, ok := e.conntrackTable()
	if !ok {
		return out
	}
	defer f.Close()
	readLive(f, client, out)
	return out
}

func readLive(r io.Reader, client string, out map[string]bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		if src, dst, ok := webrtc.LiveFlow(sc.Text()); ok && src == client {
			out[dst] = true
		}
	}
}

// condHolds evaluates a rule's if: part for a device.
func (e *Engine) condHolds(policy int, rt *match.Route, client string) bool {
	if rt.If == nil {
		return true
	}
	live := e.liveDsts(client)
	c := &e.cond
	c.mu.Lock()
	defer c.mu.Unlock()
	return rt.If.Eval(func(a *match.Expr) bool {
		for addr := range c.m[condKey{policy, rt.Raw, a.ID}] {
			if live[addr] {
				return true
			}
		}
		return false
	})
}

// RouteAction handles a lookup matching a branch of an if: (or route:)
// rule: the device's condition picks the branch (then: or else:, then
// finally:), whose action starts route or drop sessions for the device.
// matched is the name the rule matched (name, or a CNAME of it). It
// reports the action taken (match.ActRoute, match.ActDrop or "").
func (e *Engine) RouteAction(policy int, client string, addrs []string, rule, name, matched string) (string, error) {
	cfg := e.runtime()
	if cfg == nil {
		return "", nil
	}
	var rt *match.Route
	for _, p := range cfg.Policies {
		if p.ID == policy {
			rt = e.domainSet(p).Route(rule)
		}
	}
	if rt == nil {
		return "", nil
	}
	a := rt.Pick(e.condHolds(policy, rt, client), matched, name)
	if a == nil {
		return "", nil
	}
	source := SessionRule
	if a.Kind == match.ActDrop {
		source = SessionDrop
	}
	return a.Kind, e.AddSessions(policy, client, addrs, source, rule, name, a.Opts)
}
