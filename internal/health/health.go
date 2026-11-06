// Package health monitors VPN client tunnels.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

// Status is the observed health of one tunnel.
type Status struct {
	Tunnel        string    `json:"tunnel"`
	Iface         string    `json:"iface"`
	Exists        bool      `json:"exists"`
	Up            bool      `json:"up"`
	HasIPv6       bool      `json:"has_ipv6"`
	Handshake     time.Time `json:"handshake,omitempty"` // WireGuard only
	ClientState   string    `json:"client_state,omitempty"`
	LinkOK        bool      `json:"link_ok"`
	ProbeOK       bool      `json:"probe_ok"`
	ProbeFails    int       `json:"probe_fails"`
	ProbeRTT      string    `json:"probe_rtt,omitempty"`
	ExitIP        string    `json:"exit_ip,omitempty"`
	Country       string    `json:"country,omitempty"`
	GeoChecked    time.Time `json:"geo_checked,omitempty"`
	GeoError      string    `json:"geo_error,omitempty"`
	Healthy       bool      `json:"healthy"`
	HealthySince  time.Time `json:"healthy_since,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	LastChecked   time.Time `json:"last_checked"`
	everProbed    bool
	geoWasHealthy bool
}

// Monitor tracks tunnel health.
type Monitor struct {
	R system.Runner

	mu     sync.Mutex
	status map[string]*Status
}

// NewMonitor creates a monitor.
func NewMonitor(r system.Runner) *Monitor {
	return &Monitor{R: r, status: map[string]*Status{}}
}

// Snapshot returns a copy of all statuses.
func (m *Monitor) Snapshot() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.status))
	for k, v := range m.status {
		out[k] = *v
	}
	return out
}

// Get returns the status of a tunnel.
func (m *Monitor) Get(t string) (Status, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.status[t]
	if !ok {
		return Status{}, false
	}
	return *s, true
}

// Link inspects interface state without network probes (fast; used at boot
// and from hooks before the daemon has probe history).
func (m *Monitor) Link(s config.Settings, tunnel string) Status {
	st := Status{Tunnel: tunnel, Iface: config.TunnelInterface(tunnel), LastChecked: time.Now()}
	ifc, err := net.InterfaceByName(st.Iface)
	if err != nil {
		st.Reason = "interface missing"
		return st
	}
	st.Exists = true
	st.Up = ifc.Flags&net.FlagUp != 0
	if addrs, err := ifc.Addrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil && ipn.IP.IsGlobalUnicast() {
				st.HasIPv6 = true
			}
		}
	}
	if !st.Up {
		st.Reason = "interface down"
		return st
	}
	if strings.HasPrefix(tunnel, "wgc") {
		st.Handshake = m.wgHandshake(st.Iface)
		age := time.Since(st.Handshake)
		if st.Handshake.IsZero() || age > time.Duration(s.HandshakeMaxAge)*time.Second {
			st.Reason = "stale WireGuard handshake"
			return st
		}
	} else {
		unit := strings.TrimPrefix(tunnel, "ovpnc")
		st.ClientState = system.NVRAM{R: m.R}.Get("vpn_client" + unit + "_state")
		if st.ClientState != "" && st.ClientState != "2" {
			st.Reason = "OpenVPN client state " + st.ClientState
			return st
		}
	}
	st.LinkOK = true
	return st
}

func (m *Monitor) wgHandshake(iface string) time.Time {
	out, err := m.R.Run("wg", "show", iface, "latest-handshakes")
	if err != nil {
		return time.Time{}
	}
	var latest int64
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			if v, err := strconv.ParseInt(f[1], 10, 64); err == nil && v > latest {
				latest = v
			}
		}
	}
	if latest == 0 {
		return time.Time{}
	}
	return time.Unix(latest, 0)
}

// markedDialer returns a dialer whose sockets carry the tunnel probe mark, so
// they are routed through the tunnel's probe table (never WAN).
func markedDialer(mark uint32, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
}

// Probe performs a TCP connect to each target through the tunnel; any
// success counts as a pass.
func Probe(mark uint32, targets []string, timeout time.Duration) (time.Duration, error) {
	d := markedDialer(mark, timeout)
	var last error
	for _, t := range targets {
		start := time.Now()
		c, err := d.Dial("tcp4", t)
		if err == nil {
			c.Close()
			return time.Since(start), nil
		}
		last = err
	}
	return 0, last
}

// Geo looks up the tunnel's exit IP and country through the tunnel.
func Geo(mark uint32, s config.Settings) (ip, country string, err error) {
	d := markedDialer(mark, 10*time.Second)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
	}
	cl := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	req, _ := http.NewRequest("GET", s.GeoURL, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "snake-router/1")
	resp, err := cl.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("geo lookup HTTP %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&doc); err != nil {
		return "", "", err
	}
	ip = field(doc, s.GeoIPField)
	country = strings.ToUpper(field(doc, s.GeoCountryField))
	if country == "" {
		return ip, "", fmt.Errorf("geo response has no %q field", s.GeoCountryField)
	}
	return ip, country, nil
}

// field walks a dotted path like "location.country_code".
func field(doc map[string]any, path string) string {
	var cur any = doc
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}

// Check runs a full health check for a tunnel and updates the stored status.
// geoDue forces an exit-country lookup.
func (m *Monitor) Check(s config.Settings, tunnel string, geoDue bool) Status {
	st := m.Link(s, tunnel)
	m.mu.Lock()
	prev := m.status[tunnel]
	m.mu.Unlock()
	if prev != nil {
		st.ProbeFails = prev.ProbeFails
		st.ExitIP, st.Country, st.GeoChecked, st.GeoError = prev.ExitIP, prev.Country, prev.GeoChecked, prev.GeoError
		st.HealthySince = prev.HealthySince
		st.everProbed = prev.everProbed
		st.geoWasHealthy = prev.geoWasHealthy
	}
	if st.LinkOK {
		rtt, err := Probe(s.ProbeMark(tunnel), s.ProbeTargets, 5*time.Second)
		st.everProbed = true
		if err != nil {
			st.ProbeFails++
		} else {
			st.ProbeFails = 0
			st.ProbeRTT = rtt.Round(time.Millisecond).String()
		}
		st.ProbeOK = st.ProbeFails < s.ProbeFailures
		if !st.ProbeOK {
			st.Reason = fmt.Sprintf("probe failed %d times", st.ProbeFails)
		}
		// Geo check: periodic, and whenever a tunnel just became healthy
		// (a reconnect may land on a different server/country).
		if st.ProbeOK && (geoDue || !st.geoWasHealthy || time.Since(st.GeoChecked) > time.Duration(s.GeoInterval)*time.Second) {
			ip, cc, err := Geo(s.ProbeMark(tunnel), s)
			st.GeoChecked = time.Now()
			if err != nil {
				st.GeoError = err.Error()
			} else {
				st.ExitIP, st.Country, st.GeoError = ip, cc, ""
			}
		}
	} else {
		st.ProbeOK = false
		st.ProbeFails = 0
	}
	st.Healthy = st.LinkOK && st.ProbeOK
	st.geoWasHealthy = st.Healthy
	if st.Healthy {
		if st.HealthySince.IsZero() {
			st.HealthySince = time.Now()
		}
		st.Reason = ""
	} else {
		st.HealthySince = time.Time{}
	}
	m.mu.Lock()
	m.status[tunnel] = &st
	m.mu.Unlock()
	return st
}

// Seed stores a link-only status (used before the first probe cycle).
func (m *Monitor) Seed(s config.Settings, tunnel string) Status {
	st := m.Link(s, tunnel)
	st.Healthy = st.LinkOK
	if st.Healthy {
		st.HealthySince = time.Now().Add(-24 * time.Hour) // treat as long-healthy for fail-back purposes
	}
	m.mu.Lock()
	if old, ok := m.status[tunnel]; ok && old.everProbed {
		m.mu.Unlock()
		return *old
	}
	m.status[tunnel] = &st
	m.mu.Unlock()
	return st
}

// PolicyOK reports whether a tunnel is acceptable for a policy, including the
// expected exit country.
func PolicyOK(st Status, p config.Policy, strict bool) (bool, string) {
	if !st.Healthy {
		if st.Reason == "" {
			return false, "unhealthy"
		}
		return false, st.Reason
	}
	if p.ExpectedCountry != "" {
		if st.Country == "" {
			if strict {
				return false, "exit country unknown"
			}
			return true, ""
		}
		if st.Country != p.ExpectedCountry {
			return false, fmt.Sprintf("exit country %s, expected %s", st.Country, p.ExpectedCountry)
		}
	}
	return true, ""
}

// Set overrides the stored status of a tunnel (tests and manual overrides).
func (m *Monitor) Set(st Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status[st.Tunnel] = &st
}

// Prune forgets tunnels that are no longer used by any policy.
func (m *Monitor) Prune(keep []string) {
	k := map[string]bool{}
	for _, t := range keep {
		k[t] = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for t := range m.status {
		if !k[t] {
			delete(m.status, t)
		}
	}
}
