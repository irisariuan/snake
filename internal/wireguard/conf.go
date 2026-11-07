// Package wireguard parses wg-quick style configuration files and runs the
// WireGuard interfaces snake manages itself (beyond the firmware's VPN
// clients).
package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Conf is a parsed wg-quick configuration.
type Conf struct {
	PrivateKey string
	ListenPort int
	Addresses  []netip.Prefix
	MTU        int
	DNS        []string // informational: policies choose their own resolver
	Peers      []Peer
}

// Peer is one [Peer] section.
type Peer struct {
	PublicKey    string
	PresharedKey string
	Endpoint     string
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

// DefaultMTU is wg-quick's default for IPv4 + IPv6 underlay.
const DefaultMTU = 1420

// DefaultKeepalive applies when a peer sets none: WireGuard only
// handshakes when there is traffic, and snake sends nothing into a tunnel
// until its health check has seen a recent handshake.
const DefaultKeepalive = 25

// wg-quick keys snake accepts but does not act on: routing is snake's
// job, and hook scripts are not run.
var ignoredKeys = map[string]bool{
	"table": true, "fwmark": true, "saveconfig": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
}

// Parse reads a wg-quick .conf file. It needs a private key, an address
// and at least one peer with a public key and an endpoint.
func Parse(text string) (*Conf, error) {
	c := &Conf{}
	var peer *Peer
	section := ""
	for n, raw := range strings.Split(text, "\n") {
		line := raw
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		bad := func(f string, a ...any) error {
			return fmt.Errorf("line %d: %s", n+1, fmt.Sprintf(f, a...))
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				section = "interface"
			case "[peer]":
				section = "peer"
				c.Peers = append(c.Peers, Peer{})
				peer = &c.Peers[len(c.Peers)-1]
			default:
				return nil, bad("unknown section %s", line)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, bad("expected key = value")
		}
		key := strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if ignoredKeys[key] {
			continue
		}
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				if err := checkKey(v); err != nil {
					return nil, bad("PrivateKey: %v", err)
				}
				c.PrivateKey = v
			case "listenport":
				p, err := strconv.Atoi(v)
				if err != nil || p < 0 || p > 65535 {
					return nil, bad("ListenPort %q invalid", v)
				}
				c.ListenPort = p
			case "address":
				for _, a := range list(v) {
					p, err := parsePrefix(a)
					if err != nil {
						return nil, bad("Address %q invalid", a)
					}
					c.Addresses = append(c.Addresses, p)
				}
			case "mtu":
				m, err := strconv.Atoi(v)
				if err != nil || m < 1280 || m > 9000 {
					return nil, bad("MTU %q invalid (1280-9000)", v)
				}
				c.MTU = m
			case "dns":
				c.DNS = append(c.DNS, list(v)...)
			default:
				return nil, bad("unknown [Interface] key %s", strings.TrimSpace(k))
			}
		case "peer":
			switch key {
			case "publickey":
				if err := checkKey(v); err != nil {
					return nil, bad("PublicKey: %v", err)
				}
				peer.PublicKey = v
			case "presharedkey":
				if err := checkKey(v); err != nil {
					return nil, bad("PresharedKey: %v", err)
				}
				peer.PresharedKey = v
			case "endpoint":
				host, port, err := net.SplitHostPort(v)
				if p, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
					return nil, bad("Endpoint %q must be host:port", v)
				}
				peer.Endpoint = v
			case "allowedips":
				for _, a := range list(v) {
					p, err := netip.ParsePrefix(a)
					if err != nil {
						return nil, bad("AllowedIPs %q invalid", a)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, p.Masked())
				}
			case "persistentkeepalive":
				if strings.EqualFold(v, "off") {
					continue // the default applies
				}
				ka, err := strconv.Atoi(v)
				if err != nil || ka < 0 || ka > 65535 {
					return nil, bad("PersistentKeepalive %q invalid", v)
				}
				peer.Keepalive = ka
			default:
				return nil, bad("unknown [Peer] key %s", strings.TrimSpace(k))
			}
		default:
			return nil, bad("%s outside [Interface] or [Peer]", strings.TrimSpace(k))
		}
	}
	switch {
	case c.PrivateKey == "":
		return nil, fmt.Errorf("[Interface] needs a PrivateKey")
	case len(c.Addresses) == 0:
		return nil, fmt.Errorf("[Interface] needs an Address")
	case len(c.Peers) == 0:
		return nil, fmt.Errorf("needs a [Peer] section")
	}
	for i, p := range c.Peers {
		if p.PublicKey == "" {
			return nil, fmt.Errorf("peer %d needs a PublicKey", i+1)
		}
		if p.Endpoint == "" {
			return nil, fmt.Errorf("peer %d needs an Endpoint (snake connects out to the VPN server)", i+1)
		}
		if len(p.AllowedIPs) == 0 {
			return nil, fmt.Errorf("peer %d needs AllowedIPs (0.0.0.0/0, ::/0 to send any traffic)", i+1)
		}
	}
	return c, nil
}

// Setconf renders the configuration in `wg setconf` format: wg-quick's
// extra keys (Address, MTU, DNS) are applied with ip instead.
func (c *Conf) Setconf() string {
	var b strings.Builder
	b.WriteString("[Interface]\nPrivateKey = " + c.PrivateKey + "\n")
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\nPublicKey = " + p.PublicKey + "\n")
		if p.PresharedKey != "" {
			b.WriteString("PresharedKey = " + p.PresharedKey + "\n")
		}
		b.WriteString("Endpoint = " + p.Endpoint + "\n")
		ips := make([]string, len(p.AllowedIPs))
		for i, a := range p.AllowedIPs {
			ips[i] = a.String()
		}
		b.WriteString("AllowedIPs = " + strings.Join(ips, ", ") + "\n")
		ka := p.Keepalive
		if ka == 0 {
			ka = DefaultKeepalive
		}
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
	}
	return b.String()
}

// Mtu returns the configured MTU or the default.
func (c *Conf) Mtu() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return DefaultMTU
}

func checkKey(v string) error {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("not a WireGuard key (44 characters of base64)")
	}
	return nil
}

func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parsePrefix accepts "10.0.0.2/32", or a bare address as a host route.
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid address")
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}
