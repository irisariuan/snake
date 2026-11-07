package config

import (
	"strings"

	"github.com/irisariuan/snake/internal/openvpn"
	"github.com/irisariuan/snake/internal/wireguard"
)

// snake's own tunnels are saved configurations: a tunnel runs only while
// an enabled policy lists it (as its main tunnel or a failover backup).

// WireGuard is a WireGuard tunnel snake creates and runs itself, from a
// wg-quick style .conf file. Policies use it by ID like a firmware client.
type WireGuard struct {
	ID      string `json:"id"`   // wgx1 ... wgx20, also the interface name
	Name    string `json:"name"` // label shown in the web UI
	Enabled bool   `json:"enabled"`
	Conf    string `json:"conf"` // [Interface] and [Peer] sections
}

// OpenVPN is an OpenVPN client snake runs itself, from an .ovpn file with
// its certificates inline.
type OpenVPN struct {
	ID       string `json:"id"`   // ovx1 ... ovx20, also the interface name
	Name     string `json:"name"` // label shown in the web UI
	Enabled  bool   `json:"enabled"`
	Conf     string `json:"conf"`
	Username string `json:"username"` // for servers that use auth-user-pass
	Password string `json:"password"`
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

// OpenVPNTunnel returns snake's own OpenVPN client with this id.
func (c *Config) OpenVPNTunnel(id string) (OpenVPN, bool) {
	for _, o := range c.OpenVPN {
		if o.ID == id {
			return o, true
		}
	}
	return OpenVPN{}, false
}

// TunnelLabel is a tunnel's display name: "wgx1 (Tokyo)" for a named
// snake tunnel, the plain name otherwise.
func (c *Config) TunnelLabel(t string) string {
	name := ""
	if w, ok := c.WireGuardTunnel(t); ok {
		name = w.Name
	} else if o, ok := c.OpenVPNTunnel(t); ok {
		name = o.Name
	}
	if name != "" {
		return t + " (" + name + ")"
	}
	return t
}

// normalizeSnakeTunnels assigns free slots to new tunnels and tidies input.
func (c *Config) normalizeSnakeTunnels() {
	if c.WireGuard == nil {
		c.WireGuard = []WireGuard{}
	}
	if c.OpenVPN == nil {
		c.OpenVPN = []OpenVPN{}
	}
	wg := make([]*string, len(c.WireGuard))
	for i := range c.WireGuard {
		w := &c.WireGuard[i]
		w.Name = strings.TrimSpace(w.Name)
		w.Conf = tidyConf(w.Conf)
		wg[i] = &w.ID
	}
	assignSlots(wg, WireGuardName, MaxWireGuard)
	ov := make([]*string, len(c.OpenVPN))
	for i := range c.OpenVPN {
		o := &c.OpenVPN[i]
		o.Name = strings.TrimSpace(o.Name)
		o.Conf = tidyConf(o.Conf)
		o.Username = strings.TrimSpace(o.Username)
		ov[i] = &o.ID
	}
	assignSlots(ov, OpenVPNName, MaxOpenVPN)
}

func tidyConf(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")) + "\n"
}

// assignSlots gives each empty id the lowest free slot. Ids beyond the
// last slot stay empty and Validate reports them.
func assignSlots(ids []*string, name func(int) string, max int) {
	used := map[string]bool{}
	for _, id := range ids {
		*id = strings.ToLower(strings.TrimSpace(*id))
		if *id != "" {
			used[*id] = true
		}
	}
	next := 1
	for _, id := range ids {
		if *id != "" {
			continue
		}
		for next <= max && used[name(next)] {
			next++
		}
		if next > max {
			continue
		}
		*id = name(next)
		used[*id] = true
	}
}

// validateSnakeTunnels checks snake's own tunnels and returns their ids.
func (c *Config) validateSnakeTunnels(add func(string, ...any)) map[string]bool {
	s := c.Settings
	ids := map[string]bool{}
	check := func(kind, id, name string, max int, slot func(string) int, parse func() error) {
		pre := kind + " " + id + ": "
		switch {
		case id == "":
			add("at most %d %s tunnels", max, kind)
			return
		case slot(id) == 0:
			add("%s tunnel id %q invalid", kind, id)
			return
		case ids[id]:
			add("duplicate %s tunnel %q", kind, id)
		}
		ids[id] = true
		if name != "" && !nameRe.MatchString(name) {
			add(pre+"name %q invalid (1-40 chars: letters, digits, space, _.-+)", name)
		}
		if err := parse(); err != nil {
			add(pre+"%v", err)
		}
		if s.probeValue(TunnelIndex(id)) <= uint32(s.MaxPolicyID()) {
			add(pre+"mark_mask has too few bits for snake's own tunnels; use 0x%08x", DefaultMarkMask)
		}
	}
	for _, w := range c.WireGuard {
		check("WireGuard", w.ID, w.Name, MaxWireGuard, WireGuardSlot, func() error { _, err := wireguard.Parse(w.Conf); return err })
	}
	for _, o := range c.OpenVPN {
		check("OpenVPN", o.ID, o.Name, MaxOpenVPN, OpenVPNSlot, func() error {
			if strings.ContainsAny(o.Username+o.Password, "\n\r") {
				return errString("username and password must be single lines")
			}
			pc, err := openvpn.Parse(o.Conf)
			if err == nil && pc.NeedsAuth && o.Username == "" {
				return errString("the server asks for a username and password (auth-user-pass): enter them")
			}
			return err
		})
	}
	return ids
}

type errString string

func (e errString) Error() string { return string(e) }
