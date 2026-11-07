package engine

import (
	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/wireguard"
)

// NewWireGuard returns the manager of snake's own WireGuard interfaces.
func NewWireGuard(r system.Runner) *wireguard.Manager {
	return &wireguard.Manager{R: r, Owned: func(n string) bool { return config.WireGuardSlot(n) > 0 }}
}

// wireGuardTunnels lists the enabled WireGuard tunnels snake runs itself.
// Disabled and removed ones are taken down.
func wireGuardTunnels(c *config.Config) []wireguard.Tunnel {
	var out []wireguard.Tunnel
	for _, w := range c.WireGuard {
		if !w.Enabled {
			continue
		}
		conf, err := wireguard.Parse(w.Conf)
		if err != nil { // rejected by Validate; never reached with a loaded config
			logx.Warnf("wireguard %s: %v", w.ID, err)
			continue
		}
		out = append(out, wireguard.Tunnel{Name: w.ID, Conf: conf})
	}
	return out
}
