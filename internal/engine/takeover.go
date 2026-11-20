package engine

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/fwvpn"
	"github.com/irisariuan/snake/internal/logx"
)

// Taking over the firmware's VPN clients: each configured client (wgc1-5,
// ovpnc1-5) is copied into a saved tunnel of snake's own (wgx, ovx), the
// policies that used it are pointed at the copy, and the firmware client
// is stopped and switched off, so snake alone runs the VPN connections.
// The firmware client keeps its settings: turning it back on in VPN → VPN
// Client undoes its part.

// TakeOverClient is a firmware VPN client and what taking it over does.
type TakeOverClient struct {
	fwvpn.Client
	UsedBy []string `json:"used_by"` // policies listing it
	// Into is the saved tunnel it became (after a take-over).
	Into string `json:"into,omitempty"`
}

// TakeOver is the result of a preview or a take-over.
type TakeOver struct {
	Clients []TakeOverClient `json:"clients"`
	// Warnings are steps that failed after the configuration was saved
	// (a firmware client that could not be stopped).
	Warnings []string `json:"warnings,omitempty"`
	Applied  bool     `json:"applied"`
}

// readFile reads the firmware's files (tests replace it).
var takeOverReadFile = os.ReadFile

// firmwareClients reads the firmware's configured VPN clients and NVRAM.
func (e *Engine) firmwareClients() ([]fwvpn.Client, map[string]string, error) {
	out, err := e.R.Run("nvram", "show")
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read the firmware's settings: %w", err)
	}
	kv := fwvpn.ParseNVRAM(out)
	return fwvpn.Read(kv, takeOverReadFile), kv, nil
}

// TakeOverPreview lists the firmware's VPN clients and the policies using
// them, without changing anything.
func (e *Engine) TakeOverPreview() (TakeOver, error) {
	clients, _, err := e.firmwareClients()
	if err != nil {
		return TakeOver{}, err
	}
	return TakeOver{Clients: withUsers(e.Config(), clients)}, nil
}

func withUsers(c *config.Config, clients []fwvpn.Client) []TakeOverClient {
	out := make([]TakeOverClient, 0, len(clients))
	for _, cl := range clients {
		t := TakeOverClient{Client: cl, UsedBy: []string{}}
		for _, p := range c.Policies {
			for _, tn := range p.Tunnels {
				if tn == cl.ID {
					t.UsedBy = append(t.UsedBy, p.Name)
				}
			}
		}
		out = append(out, t)
	}
	return out
}

// freeSlot returns the lowest id of name(1..max) not in used, and marks it.
func freeSlot(used map[string]bool, name func(int) string, max int) string {
	for n := 1; n <= max; n++ {
		if id := name(n); !used[id] {
			used[id] = true
			return id
		}
	}
	return ""
}

// takeOverInto copies the clients into c as saved tunnels and points the
// policies at them. It returns the saved tunnel of each client.
func takeOverInto(c *config.Config, clients []fwvpn.Client) (map[string]string, error) {
	used := map[string]bool{}
	for _, w := range c.WireGuard {
		used[w.ID] = true
	}
	for _, o := range c.OpenVPN {
		used[o.ID] = true
	}
	// A client taken over before is not copied again: its copy is reused.
	same := func(a, b string) bool {
		return strings.TrimSpace(strings.ReplaceAll(a, "\r\n", "\n")) == strings.TrimSpace(strings.ReplaceAll(b, "\r\n", "\n"))
	}
	existing := func(cl fwvpn.Client) string {
		for _, w := range c.WireGuard {
			if cl.Kind == fwvpn.WireGuard && same(w.Conf, cl.Conf) {
				return w.ID
			}
		}
		for _, o := range c.OpenVPN {
			if cl.Kind == fwvpn.OpenVPN && same(o.Conf, cl.Conf) {
				return o.ID
			}
		}
		return ""
	}
	into := map[string]string{}
	for _, cl := range clients {
		if id := existing(cl); id != "" {
			into[cl.ID] = id
			continue
		}
		name := cl.ID
		if d := tunnelName(cl.Name); d != "" {
			name = cl.ID + " " + d
		}
		if len(name) > 40 {
			name = strings.TrimSpace(name[:40])
		}
		switch cl.Kind {
		case fwvpn.WireGuard:
			id := freeSlot(used, config.WireGuardName, config.MaxWireGuard)
			if id == "" {
				return nil, fmt.Errorf("no free WireGuard slot for %s (all %d saved tunnels are in use)", cl.ID, config.MaxWireGuard)
			}
			c.WireGuard = append(c.WireGuard, config.WireGuard{ID: id, Name: name, Enabled: true, Conf: cl.Conf})
			into[cl.ID] = id
		case fwvpn.OpenVPN:
			id := freeSlot(used, config.OpenVPNName, config.MaxOpenVPN)
			if id == "" {
				return nil, fmt.Errorf("no free OpenVPN slot for %s (all %d saved tunnels are in use)", cl.ID, config.MaxOpenVPN)
			}
			c.OpenVPN = append(c.OpenVPN, config.OpenVPN{ID: id, Name: name, Enabled: true, Conf: cl.Conf, Username: cl.Username, Password: cl.Password})
			into[cl.ID] = id
		}
	}
	for i := range c.Policies {
		p := &c.Policies[i]
		for j, t := range p.Tunnels {
			if n, ok := into[t]; ok {
				p.Tunnels[j] = n
			}
		}
	}
	return into, nil
}

// tunnelName keeps the characters a saved tunnel's name may have.
func tunnelName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune(" _.-+", r):
			b.WriteRune(r)
		default:
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// TakeOverClients takes over the firmware clients with these ids (every
// client that can be taken over when ids is empty).
func (e *Engine) TakeOverClients(ids []string) (TakeOver, error) {
	all, kv, err := e.firmwareClients()
	if err != nil {
		return TakeOver{}, err
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[strings.ToLower(strings.TrimSpace(id))] = true
	}
	var take []fwvpn.Client
	for _, cl := range all {
		if len(want) > 0 && !want[cl.ID] {
			continue
		}
		delete(want, cl.ID)
		if cl.Error != "" {
			if len(ids) > 0 {
				return TakeOver{}, fmt.Errorf("%s cannot be taken over: %s", cl.ID, cl.Error)
			}
			continue
		}
		take = append(take, cl)
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for id := range want {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		return TakeOver{}, fmt.Errorf("not a configured firmware VPN client: %s", strings.Join(missing, ", "))
	}
	if len(take) == 0 {
		return TakeOver{}, fmt.Errorf("no firmware VPN client can be taken over")
	}

	e.cfgMu.Lock()
	defer e.cfgMu.Unlock()
	// Check the new configuration before touching the firmware.
	c := e.Config()
	before := withUsers(c, all)
	into, err := takeOverInto(c, take)
	if err != nil {
		return TakeOver{}, err
	}
	c.ApplyDefaults()
	c.Normalize()
	if err := c.Validate(); err != nil {
		return TakeOver{}, err
	}
	// Firmware clients stop first: a VPN server accepts one connection per
	// key or account, so the copy must not start beside the original.
	res := TakeOver{Applied: true}
	if !e.DryRun {
		res.Warnings = e.stopFirmwareClients(take, kv)
	}
	if err := e.SetConfig(c); err != nil {
		res.Warnings = append(res.Warnings, "saved, but applying had errors: "+err.Error())
	}
	for _, t := range before {
		t.Into = into[t.ID]
		res.Clients = append(res.Clients, t)
		if t.Into != "" {
			e.event("", "tunnel", "took over firmware VPN client %s as %s", t.ID, t.Into)
		}
	}
	return res, nil
}

// stopFirmwareClients stops the clients and keeps the firmware from
// starting them again. It returns what failed.
func (e *Engine) stopFirmwareClients(clients []fwvpn.Client, kv map[string]string) []string {
	var warns []string
	run := func(what string, name string, args ...string) {
		if _, err := e.R.Run(name, args...); err != nil {
			logx.Warnf("take over: %s: %v", what, err)
			warns = append(warns, what+" failed: turn it off in VPN → VPN Client")
		}
	}
	eas, easChanged := kv["vpn_clientx_eas"], false
	for _, cl := range clients {
		switch cl.Kind {
		case fwvpn.WireGuard:
			run("switching off "+cl.ID, "nvram", "set", fmt.Sprintf("wgc%d_enable=0", cl.Num))
			run("stopping "+cl.ID, "service", fmt.Sprintf("stop_wgc %d", cl.Num))
		case fwvpn.OpenVPN:
			// Start at boot: a list of client numbers on older firmware,
			// a setting per client on newer.
			var keep []string
			for _, n := range strings.Split(eas, ",") {
				if n = strings.TrimSpace(n); n != "" && n != fmt.Sprint(cl.Num) {
					keep = append(keep, n)
				} else if n != "" {
					easChanged = true
				}
			}
			eas = strings.Join(keep, ",")
			if eas != "" {
				eas += ","
			}
			if _, ok := kv[fmt.Sprintf("vpn_client%d_enable", cl.Num)]; ok {
				run("switching off "+cl.ID, "nvram", "set", fmt.Sprintf("vpn_client%d_enable=0", cl.Num))
			}
			run("stopping "+cl.ID, "service", fmt.Sprintf("stop_vpnclient%d", cl.Num))
		}
	}
	if easChanged {
		run("switching off the OpenVPN clients' start at boot", "nvram", "set", "vpn_clientx_eas="+eas)
	}
	run("saving the firmware's settings", "nvram", "commit")
	return warns
}
