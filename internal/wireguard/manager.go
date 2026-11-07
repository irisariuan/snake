package wireguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/irisariuan/snake/internal/system"
)

// Tunnel is an interface to run.
type Tunnel struct {
	Name string // interface name (wgx1...)
	Conf *Conf
}

// Manager creates, configures and removes snake's WireGuard interfaces
// with `ip` and `wg`. Interfaces carry no routes of their own: snake's
// policy tables route into them, so wg-quick's AllowedIPs routing and
// DNS handling are not used.
type Manager struct {
	R system.Runner
	// Owned reports whether an interface name is one of snake's (wgx1...).
	Owned func(name string) bool

	mu      sync.Mutex
	applied map[string]string // interface -> hash of the configuration set
}

// Sync brings the interfaces to the wanted state and removes snake's
// interfaces that are no longer wanted.
func (m *Manager) Sync(want []Tunnel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applied == nil {
		m.applied = map[string]string{}
	}
	var errs []string
	keep := map[string]bool{}
	for _, t := range want {
		keep[t.Name] = true
		if err := m.up(t); err != nil {
			errs = append(errs, fmt.Sprintf("wireguard %s: %v", t.Name, err))
			delete(m.applied, t.Name)
		}
	}
	for _, n := range m.existing() {
		if !keep[n] {
			if _, err := m.R.Run("ip", "link", "del", "dev", n); err != nil {
				errs = append(errs, fmt.Sprintf("wireguard %s: remove: %v", n, err))
			}
			delete(m.applied, n)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// RemoveAll deletes every interface snake created.
func (m *Manager) RemoveAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.existing() {
		_, _ = m.R.Run("ip", "link", "del", "dev", n)
	}
	m.applied = map[string]string{}
}

func (m *Manager) up(t Tunnel) error {
	created := false
	if _, err := m.R.Run("ip", "link", "show", "dev", t.Name); err != nil {
		if _, err := m.R.Run("ip", "link", "add", "dev", t.Name, "type", "wireguard"); err != nil {
			// The module is normally loaded on demand; try once by hand.
			_, _ = m.R.Run("modprobe", "wireguard")
			if _, err2 := m.R.Run("ip", "link", "add", "dev", t.Name, "type", "wireguard"); err2 != nil {
				return fmt.Errorf("create interface (does this firmware have WireGuard?): %v", err)
			}
		}
		created = true
	}
	conf := t.Conf.Setconf()
	sum := sha256.Sum256([]byte(conf))
	h := hex.EncodeToString(sum[:])
	if created || m.applied[t.Name] != h {
		// syncconf keeps the sessions of unchanged peers; setconf is the
		// fallback for old wg tools and for a fresh interface.
		var err error
		if !created {
			_, err = m.R.RunInput(conf, "wg", "syncconf", t.Name, "/dev/stdin")
		}
		if created || err != nil {
			if _, err = m.R.RunInput(conf, "wg", "setconf", t.Name, "/dev/stdin"); err != nil {
				return fmt.Errorf("configure: %v", redact(err, t.Conf))
			}
		}
		m.applied[t.Name] = h
	}
	if err := m.addresses(t); err != nil {
		return err
	}
	if _, err := m.R.Run("ip", "link", "set", "dev", t.Name, "mtu", strconv.Itoa(t.Conf.Mtu()), "up"); err != nil {
		return fmt.Errorf("bring up: %v", err)
	}
	return nil
}

// addresses makes the interface carry exactly the configured addresses
// (IPv6 link-local addresses are the kernel's and left alone).
func (m *Manager) addresses(t Tunnel) error {
	out, _ := m.R.Run("ip", "-o", "addr", "show", "dev", t.Name)
	have := map[netip.Prefix]bool{}
	for _, p := range parseAddrs(out) {
		have[p] = true
	}
	want := map[netip.Prefix]bool{}
	for _, p := range t.Conf.Addresses {
		want[p] = true
		if have[p] {
			continue
		}
		if _, err := m.R.Run("ip", "addr", "add", p.String(), "dev", t.Name); err != nil {
			return fmt.Errorf("address %s: %v", p, err)
		}
	}
	var stale []string
	for p := range have {
		if !want[p] && !p.Addr().IsLinkLocalUnicast() {
			stale = append(stale, p.String())
		}
	}
	sort.Strings(stale)
	for _, p := range stale {
		_, _ = m.R.Run("ip", "addr", "del", p, "dev", t.Name)
	}
	return nil
}

// existing lists snake's interfaces present in the kernel.
func (m *Manager) existing() []string {
	out, err := m.R.Run("ip", "-o", "link", "show")
	if err != nil {
		return nil
	}
	var names []string
	for _, n := range parseLinks(out) {
		if m.Owned != nil && m.Owned(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// parseLinks extracts interface names from `ip -o link show`:
// "12: wgx1: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 ...".
func parseLinks(out string) []string {
	var names []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		n := strings.TrimSuffix(f[1], ":")
		if i := strings.IndexByte(n, '@'); i >= 0 {
			n = n[:i]
		}
		names = append(names, n)
	}
	return names
}

// parseAddrs extracts prefixes from `ip -o addr show`:
// "12: wgx1    inet 10.2.0.2/32 scope global wgx1\       valid_lft ...".
func parseAddrs(out string) []netip.Prefix {
	var ps []netip.Prefix
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] != "inet" && f[i] != "inet6" {
				continue
			}
			if p, err := parsePrefix(f[i+1]); err == nil {
				ps = append(ps, p)
			}
			break
		}
	}
	return ps
}

// redact keeps keys out of error messages (wg echoes bad lines).
func redact(err error, c *Conf) string {
	s := err.Error()
	for _, k := range []string{c.PrivateKey} {
		if k != "" {
			s = strings.ReplaceAll(s, k, "(private key)")
		}
	}
	for _, p := range c.Peers {
		if p.PresharedKey != "" {
			s = strings.ReplaceAll(s, p.PresharedKey, "(preshared key)")
		}
	}
	return s
}
