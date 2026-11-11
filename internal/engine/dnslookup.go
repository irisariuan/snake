package engine

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsfwd"
	"github.com/irisariuan/snake/internal/dnslookup"
	"github.com/irisariuan/snake/internal/system"
)

// resolvDnsmasq lists dnsmasq's upstream resolvers (Asuswrt).
var resolvDnsmasq = "/tmp/resolv.dnsmasq"

// Paths of a DNS lookup.
const (
	ViaRouter = "router" // the router's dnsmasq, as LAN devices ask it
	ViaWAN    = "wan"    // straight to a resolver, routed like the router's own traffic
)

// DefaultLookupServer is asked when a lookup through WAN or a tunnel names
// no resolver.
const DefaultLookupServer = "1.1.1.1"

// Hop is one step of the path a DNS query took.
type Hop struct {
	What   string `json:"what"`
	Detail string `json:"detail,omitempty"`
}

// LookupResult is a DNS lookup with the path its query took.
type LookupResult struct {
	dnslookup.Result
	Route []Hop `json:"route"`
}

// LookupPaths are the paths a lookup can take, and the router's WAN DNS
// setting the WAN path uses by default.
type LookupPaths struct {
	Vias   []string `json:"vias"` // router, wan and each tunnel in use
	WANDNS WANDNS   `json:"wan_dns"`
}

// LookupVias lists the paths a lookup can take.
func (e *Engine) LookupVias() LookupPaths {
	return LookupPaths{Vias: append([]string{ViaRouter, ViaWAN}, usedTunnels(e.runtime())...), WANDNS: e.wanDNS()}
}

// stubbyAddr is where Merlin's DNS-over-TLS client (Stubby) listens.
const stubbyAddr = "127.0.1.1"

// WANDNS is the router's own WAN DNS setting: the resolvers dnsmasq
// forwards names to that no policy resolves through a tunnel.
type WANDNS struct {
	// Servers are asked in this order (127.0.1.1 when DoT is on).
	Servers []string `json:"servers"`
	// DoT: WAN DNS goes to Stubby, which sends it over TLS to DoTServers.
	DoT        bool     `json:"dot,omitempty"`
	DoTServers []string `json:"dot_servers,omitempty"`
	Source     string   `json:"source"`
}

// wanDNS reads the router's WAN DNS setting: DNS-over-TLS (nvram
// dnspriv_*), else dnsmasq's resolv file, else nvram wan0_dns.
func (e *Engine) wanDNS() WANDNS {
	nv := system.NVRAM{R: e.R}
	if strings.TrimSpace(nv.Get("dnspriv_enable")) == "1" {
		w := WANDNS{Servers: []string{stubbyAddr}, DoT: true, Source: "WAN → DNS Privacy Protocol: DNS-over-TLS"}
		// <addr>port>tls name>spki pin<addr>...
		for _, ent := range strings.Split(nv.Get("dnspriv_rulelist"), "<") {
			f := strings.Split(ent, ">")
			if strings.TrimSpace(f[0]) == "" {
				continue
			}
			d := f[0]
			if len(f) > 1 && f[1] != "" {
				d = net.JoinHostPort(f[0], f[1])
			}
			if len(f) > 2 && f[2] != "" {
				d += " (" + f[2] + ")"
			}
			w.DoTServers = append(w.DoTServers, d)
		}
		return w
	}
	if ups := dnsmasqUpstreams(); len(ups) > 0 {
		return WANDNS{Servers: ups, Source: resolvDnsmasq}
	}
	var out []string
	for _, k := range []string{"wan0_dns", "wan1_dns"} {
		for _, f := range strings.Fields(nv.Get(k)) {
			if _, err := netip.ParseAddr(f); err == nil {
				out = append(out, f)
			}
		}
	}
	return WANDNS{Servers: out, Source: "nvram wan0_dns"}
}

// wanDNSHops is the route from the router to its WAN DNS: Stubby and its
// DoT servers, or the first resolver, with the kernel route to it.
func (e *Engine) wanDNSHops(w WANDNS) []Hop {
	if w.DoT {
		h := []Hop{{What: "Stubby on " + stubbyAddr + ":53", Detail: "the router's DNS-over-TLS client (" + w.Source + ")"}}
		if len(w.DoTServers) == 0 {
			return append(h, Hop{What: "DNS-over-TLS servers", Detail: "none listed in nvram dnspriv_rulelist"})
		}
		h = append(h, Hop{What: "Sent over TLS to " + strings.Join(w.DoTServers, ", "), Detail: "the ISP sees TLS to port 853, not the query"})
		host, _, err := net.SplitHostPort(strings.SplitN(w.DoTServers[0], " ", 2)[0])
		if err != nil {
			host = strings.SplitN(w.DoTServers[0], " ", 2)[0]
		}
		if a, err := netip.ParseAddr(host); err == nil {
			h = append(h, e.kernelRoute(a, 0, "")...)
		}
		return h
	}
	if len(w.Servers) == 0 {
		return []Hop{{What: "The router's WAN DNS servers", Detail: "unknown (" + resolvDnsmasq + " not readable, nvram wan0_dns empty)"}}
	}
	h := []Hop{{What: "The router's WAN DNS: " + strings.Join(w.Servers, ", "), Detail: "from " + w.Source}}
	if a, err := netip.ParseAddr(w.Servers[0]); err == nil {
		h = append(h, e.kernelRoute(a, 0, "")...)
	}
	return h
}

// DNSLookup asks a resolver for records of name over the chosen path
// (ViaRouter, ViaWAN or a tunnel in use) and reports the route the query
// took.
func (e *Engine) DNSLookup(name, typ, via, server string) LookupResult {
	cfg := e.runtime()
	if via == "" {
		via = ViaRouter
	}
	var res LookupResult
	fail := func(msg string) LookupResult {
		n, t := dnslookup.QueryName(name, strings.ToUpper(typ))
		res.Result = dnslookup.Result{Name: n, Type: t, Via: via, Records: []dnslookup.Record{}, Error: msg}
		return res
	}
	if strings.TrimSpace(name) == "" {
		return fail("name required")
	}
	timeout := 5 * time.Second
	var dial dnslookup.Dialer
	switch via {
	case ViaRouter:
		server = "127.0.0.1:53"
		d := &net.Dialer{}
		dial = d.DialContext
		qn, _ := dnslookup.QueryName(name, typ)
		res.Route = e.routerRoute(cfg, qn)
	default:
		tunnel := ""
		if via != ViaWAN {
			for _, t := range usedTunnels(cfg) {
				if t == via {
					tunnel = t
				}
			}
			if tunnel == "" {
				return fail("unknown path " + strconv.Quote(via) + ": router, wan or a tunnel in use")
			}
		}
		var wan *WANDNS
		defaulted := strings.TrimSpace(server) == ""
		if defaulted {
			server = DefaultLookupServer
			// WAN: the router's own WAN DNS setting, as dnsmasq uses it.
			if tunnel == "" {
				if w := e.wanDNS(); len(w.Servers) > 0 {
					server, wan = w.Servers[0], &w
				}
			}
		}
		s, err := dnslookup.Server(server)
		if err != nil {
			return fail(err.Error())
		}
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			// A name would need a lookup of its own, over a path we
			// could not show.
			return fail("resolver must be an IP address")
		}
		server = s
		switch {
		case tunnel == "" && wan != nil:
			d := &net.Dialer{}
			dial = d.DialContext
			res.Route = append([]Hop{{What: "Sent by the router itself, without a policy mark", Detail: "routed like the router's own traffic"}}, e.wanDNSHops(*wan)...)
			if !wan.DoT {
				res.Route = append(res.Route, Hop{What: "Resolver " + server, Detail: "the router's WAN DNS setting"})
			}
		case tunnel == "":
			d := &net.Dialer{}
			dial = d.DialContext
			res.Route = append([]Hop{{What: "Sent by the router itself, without a policy mark", Detail: "routed like the router's own traffic"}},
				e.kernelRoute(ap.Addr(), 0, "")...)
			h := Hop{What: "Resolver " + server}
			if defaulted {
				h.Detail = "no WAN DNS setting found on the router, so " + DefaultLookupServer + " is asked"
			}
			res.Route = append(res.Route, h)
		default:
			mark, ifc := cfg.Settings.ProbeMark(tunnel), config.TunnelInterface(tunnel)
			dial = dnsfwd.Dialer(mark, ifc, timeout).DialContext
			res.Route = append([]Hop{{What: "Sent through tunnel " + tunnel, Detail: fmt.Sprintf("socket mark 0x%x, bound to %s so it cannot leave by another interface", mark, ifc)}},
				e.kernelRoute(ap.Addr(), mark, ifc)...)
			res.Route = append(res.Route, e.exitHop(tunnel), Hop{What: "Resolver " + server})
		}
	}
	res.Result = dnslookup.Lookup(dial, server, name, typ, timeout)
	res.Via = via
	if via != ViaRouter && via != ViaWAN && strings.Contains(res.Error, "no such device") {
		res.Error += " (the tunnel's interface does not exist: the tunnel is down, and the query was not sent another way)"
	}
	return res
}

// routerRoute is the path dnsmasq gives a query for name: a policy that
// resolves its domains through its tunnel, or dnsmasq's upstreams.
func (e *Engine) routerRoute(cfg *config.Config, name string) []Hop {
	route := []Hop{{What: "dnsmasq on the router (127.0.0.1:53)", Detail: "as LAN devices ask it; it may answer from its cache"}}
	// dnsmasq's server=/domain/ picks the longest matching domain.
	var best config.Policy
	base := ""
	for _, p := range cfg.Policies {
		if !p.Enabled || !p.Leak.DNSViaTunnel || p.Leak.DNSServer == "" || !p.HasDomains() {
			continue
		}
		for _, b := range p.DomainRules().Bases() {
			if (name == b || strings.HasSuffix(name, "."+b)) && len(b) > len(base) {
				best, base = p, b
			}
		}
	}
	if base != "" {
		p := best
		route = append(route, Hop{What: "Policy " + p.Name + " resolves " + base + " through its tunnel", Detail: "dnsmasq server=/" + base + "/ rule"})
		e.mu.Lock()
		tunnel := e.active[p.ID]
		e.mu.Unlock()
		if tunnel == "" {
			d := "dnsmasq answers the name locally (no address)"
			if p.Leak.Encrypted() {
				d = "snake's forwarder answers SERVFAIL without sending the query"
			}
			return append(route, Hop{What: "No healthy tunnel: the query is not sent", Detail: d})
		}
		mark, ifc := cfg.Settings.ProbeMark(tunnel), config.TunnelInterface(tunnel)
		port := 53
		proto := "plain DNS"
		switch p.Leak.DNSProtocol {
		case config.DNSDoT:
			port, proto = 853, "DNS over TLS ("+p.Leak.DNSTLSName+")"
		case config.DNSDoH:
			port, proto = 443, "DNS over HTTPS ("+p.Leak.DNSTLSName+p.Leak.DNSDoHPath+")"
		}
		if p.Leak.Encrypted() {
			route = append(route, Hop{What: "snake's forwarder 127.0.0.1:" + strconv.Itoa(cfg.Settings.DNSForwardPort+p.ID), Detail: "encrypts the query"})
		}
		route = append(route, Hop{What: "Sent through tunnel " + tunnel, Detail: fmt.Sprintf("bound to %s, mark 0x%x", ifc, mark)})
		if a, err := netip.ParseAddr(p.Leak.DNSServer); err == nil {
			route = append(route, e.kernelRoute(a, mark, ifc)...)
		}
		route = append(route, e.exitHop(tunnel))
		return append(route, Hop{What: "Resolver " + net.JoinHostPort(p.Leak.DNSServer, strconv.Itoa(port)), Detail: proto})
	}
	route = append(route, Hop{What: "No policy resolves this name through a tunnel", Detail: "dnsmasq forwards it to the router's WAN DNS"})
	return append(route, e.wanDNSHops(e.wanDNS())...)
}

// dnsmasqUpstreams reads the servers of resolv.dnsmasq ("server=IP" or
// "nameserver IP" lines).
func dnsmasqUpstreams() []string {
	b, err := os.ReadFile(resolvDnsmasq)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		var v string
		switch {
		case strings.HasPrefix(l, "server="):
			v = strings.TrimPrefix(l, "server=")
		case strings.HasPrefix(l, "nameserver"):
			v = strings.TrimSpace(strings.TrimPrefix(l, "nameserver"))
		default:
			continue
		}
		// server=/domain/IP is domain-specific: not a default upstream.
		if v != "" && !strings.HasPrefix(v, "/") {
			out = append(out, strings.SplitN(v, "#", 2)[0])
		}
	}
	return out
}

// kernelRoute asks the kernel how a packet to dst with mark (bound to
// iface) is routed: `ip route get`.
func (e *Engine) kernelRoute(dst netip.Addr, mark uint32, iface string) []Hop {
	args := []string{"route", "get", dst.String()}
	if dst.Is6() {
		args = append([]string{"-6"}, args...)
	}
	if mark != 0 {
		args = append(args, "mark", fmt.Sprintf("0x%x", mark))
	}
	if iface != "" {
		args = append(args, "oif", iface)
	}
	out, err := e.R.Run("ip", args...)
	if err != nil {
		return []Hop{{What: "Kernel route unknown", Detail: strings.TrimSpace(out + " " + err.Error())}}
	}
	r := parseRouteGet(out)
	if r["dev"] == "" {
		if strings.TrimSpace(out) == "" {
			return []Hop{{What: "Kernel route unknown", Detail: "no output from ip route get"}}
		}
		return []Hop{{What: "Kernel route", Detail: strings.TrimSpace(out)}}
	}
	what := "Out interface " + r["dev"]
	if t := e.tunnelOfIface(r["dev"]); t != "" {
		what += " (tunnel " + t + ")"
	} else if iface == "" {
		what += e.wanLabel(r["src"])
	}
	var d []string
	if r["via"] != "" {
		d = append(d, "gateway "+r["via"])
	}
	if r["src"] != "" {
		d = append(d, "source "+r["src"])
	}
	if r["table"] != "" {
		d = append(d, "table "+r["table"])
	}
	return []Hop{{What: what, Detail: strings.Join(d, ", ")}}
}

// parseRouteGet reads the keyword/value pairs of `ip route get` output.
func parseRouteGet(out string) map[string]string {
	r := map[string]string{}
	line := strings.SplitN(strings.TrimSpace(out), "\n", 2)[0]
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "dev", "via", "src", "table":
			if r[f[i]] == "" {
				r[f[i]] = f[i+1]
			}
		}
	}
	return r
}

func (e *Engine) tunnelOfIface(ifc string) string {
	ts := usedTunnels(e.runtime())
	sort.Strings(ts)
	for _, t := range ts {
		if config.TunnelInterface(t) == ifc {
			return t
		}
	}
	return ""
}

// wanLabel marks a source address that is the router's WAN address.
func (e *Engine) wanLabel(src string) string {
	for _, a := range e.wanAddrs() {
		if a == src {
			return " (WAN, the ISP sees this query)"
		}
	}
	return ""
}

func (e *Engine) exitHop(tunnel string) Hop {
	st, ok := e.mon.Get(tunnel)
	if !ok || st.ExitIP == "" {
		return Hop{What: "Tunnel exit", Detail: "not known yet"}
	}
	h := Hop{What: "Leaves the tunnel at " + st.ExitIP + " " + st.Country, Detail: "the resolver sees this address"}
	if !st.Healthy {
		h.Detail += "; tunnel currently unhealthy: " + st.Reason
	}
	return h
}
