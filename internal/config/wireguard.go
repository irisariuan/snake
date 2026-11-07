package config

import "strings"

// WireGuard is a WireGuard tunnel snake creates and runs itself, from a
// wg-quick style .conf file. Policies use it by ID like a firmware client.
type WireGuard struct {
	ID      string `json:"id"`   // wgx1 ... wgx20, also the interface name
	Name    string `json:"name"` // label shown in the web UI
	Enabled bool   `json:"enabled"`
	Conf    string `json:"conf"` // [Interface] and [Peer] sections
}

// WireGuardTunnel returns snake's own WireGuard tunnel with this id.
func (c *Config) WireGuardTunnel(id string) (WireGuard, bool) {
	for _, w := range c.WireGuard {
		if w.ID == id {
			return w, true
		}
	}
	return WireGuard{}, false
}

// TunnelLabel is a tunnel's display name: "wgx1 (Tokyo)" for a named
// WireGuard tunnel, the plain name otherwise.
func (c *Config) TunnelLabel(t string) string {
	if w, ok := c.WireGuardTunnel(t); ok && w.Name != "" {
		return t + " (" + w.Name + ")"
	}
	return t
}

// normalizeWireGuard assigns free slots to new tunnels and tidies input.
func (c *Config) normalizeWireGuard() {
	used := map[string]bool{}
	for i := range c.WireGuard {
		w := &c.WireGuard[i]
		w.ID = strings.ToLower(strings.TrimSpace(w.ID))
		if w.ID != "" {
			used[w.ID] = true
		}
	}
	next := 1
	for i := range c.WireGuard {
		w := &c.WireGuard[i]
		w.Name = strings.TrimSpace(w.Name)
		w.Conf = strings.TrimSpace(strings.ReplaceAll(w.Conf, "\r\n", "\n")) + "\n"
		if w.ID != "" {
			continue
		}
		for next <= MaxWireGuard && used[WireGuardName(next)] {
			next++
		}
		if next > MaxWireGuard {
			continue // left empty: Validate reports it
		}
		w.ID = WireGuardName(next)
		used[w.ID] = true
	}
}
