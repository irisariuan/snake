package engine

import (
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/openvpn"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/wireguard"
)

// snake's own tunnels (wgx, ovx) are saved configurations. One runs only
// while an enabled policy lists it, as its main tunnel or a failover
// backup, so backups are connected and health-checked before a failover.

// NewWireGuard returns the manager of snake's own WireGuard interfaces.
func NewWireGuard(r system.Runner) *wireguard.Manager {
	return &wireguard.Manager{R: r, Owned: func(n string) bool { return config.WireGuardSlot(n) > 0 }}
}

// NewOpenVPN returns the manager of snake's own OpenVPN clients.
func NewOpenVPN(r system.Runner) *openvpn.Manager {
	return openvpn.NewManager(r, func(n string) bool { return config.OpenVPNSlot(n) > 0 })
}

// neededTunnels returns snake's enabled tunnels that enabled policies use.
func neededTunnels(c *config.Config) ([]wireguard.Tunnel, []openvpn.Tunnel) {
	var wgs []wireguard.Tunnel
	var ovs []openvpn.Tunnel
	for _, t := range usedTunnels(c) {
		if w, ok := c.WireGuardTunnel(t); ok && w.Enabled {
			conf, err := wireguard.Parse(w.Conf)
			if err != nil { // rejected by Validate; never reached with a loaded config
				logx.Warnf("wireguard %s: %v", w.ID, err)
				continue
			}
			wgs = append(wgs, wireguard.Tunnel{Name: w.ID, Conf: conf})
		}
		if o, ok := c.OpenVPNTunnel(t); ok && o.Enabled {
			conf, err := openvpn.Parse(o.Conf)
			if err != nil {
				logx.Warnf("openvpn %s: %v", o.ID, err)
				continue
			}
			ovs = append(ovs, openvpn.Tunnel{Name: o.ID, Conf: conf, Username: o.Username, Password: o.Password})
		}
	}
	return wgs, ovs
}

// syncSnakeTunnels starts the needed tunnels and stops the others.
func (e *Engine) syncSnakeTunnels(c *config.Config) []string {
	var errs []string
	wgs, ovs := neededTunnels(c)
	if err := e.wg.Sync(wgs); err != nil {
		errs = append(errs, err.Error())
	}
	started, err := e.ovpn.Sync(ovs)
	if err != nil {
		errs = append(errs, err.Error())
	}
	e.noteStarted(started)
	return errs
}

// restartOpenVPN starts needed OpenVPN clients that exited.
func (e *Engine) restartOpenVPN(c *config.Config) {
	_, ovs := neededTunnels(c)
	started, err := e.ovpn.Sync(ovs)
	if err != nil {
		logx.Warnf("%v", err)
	}
	e.noteStarted(started)
}

// noteStarted logs started clients and checks their health again once
// they had time to connect, instead of waiting a whole health interval.
func (e *Engine) noteStarted(started []string) {
	for _, n := range started {
		e.event("", "tunnel", "started OpenVPN client %s", n)
	}
	if len(started) > 0 && e.isDaemon() {
		go func() {
			time.Sleep(8 * time.Second)
			e.Kick()
		}()
	}
}
