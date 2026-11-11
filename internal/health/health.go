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
	Tunnel      string    `json:"tunnel"`
	Iface       string    `json:"iface"`
	Exists      bool      `json:"exists"`
	Up          bool      `json:"up"`
	HasIPv6     bool      `json:"has_ipv6"`
	Handshake   time.Time `json:"handshake,omitempty"` // WireGuard only
	ClientState string    `json:"client_state,omitempty"`
	LinkOK      bool      `json:"link_ok"`
	ProbeOK     bool      `json:"probe_ok"`
	ProbeFails  int       `json:"probe_fails"`
	ProbeRTT    string    `json:"probe_rtt,omitempty"`
	// RTTMs is the smoothed probe round trip in milliseconds (0 = no
	// sample yet), Loss the smoothed share of failed probes (0-1).
	RTTMs float64 `json:"rtt_ms,omitempty"`
	Loss  float64 `json:"loss"`
	// ThroughputMbps is the last measured download speed through the
	// tunnel (0 = not measured), for policies selecting by speed.
	ThroughputMbps float64   `json:"throughput_mbps,omitempty"`
	SpeedChecked   time.Time `json:"speed_checked,omitempty"`
	SpeedError     string    `json:"speed_error,omitempty"`
	// SpeedTesting is set while a speed test of the tunnel runs or is
	// queued behind another tunnel's.
	SpeedTesting  bool      `json:"speed_testing,omitempty"`
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
	speed  map[string]*speedState

	// speedTest measures throughput (SpeedTest; replaced in tests).
	speedTest func(mark uint32, url string) (float64, error)
	// speedMu runs one speed test at a time, so tunnels do not compete
	// for the WAN's bandwidth.
	speedMu sync.Mutex
}

// speedState is a tunnel's last throughput measurement.
type speedState struct {
	mbps    float64
	checked time.Time
	err     string
	running bool
	// force makes the next check test the tunnel whatever its age
	// (RecheckSpeed).
	force bool
}

// NewMonitor creates a monitor.
func NewMonitor(r system.Runner) *Monitor {
	return &Monitor{R: r, status: map[string]*Status{}, speed: map[string]*speedState{}, speedTest: SpeedTest}
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
	if config.IsWireGuard(tunnel) {
		st.Handshake = m.wgHandshake(st.Iface)
		age := time.Since(st.Handshake)
		if st.Handshake.IsZero() || age > time.Duration(s.HandshakeMaxAge)*time.Second {
			st.Reason = "stale WireGuard handshake"
			return st
		}
	} else if strings.HasPrefix(tunnel, "ovpnc") {
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

// probe is Probe (replaced in tests).
var probe = Probe

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

// Speed test limits.
var (
	speedTimeout  = 30 * time.Second
	speedMaxBytes = int64(50 << 20)
	speedMinBytes = int64(256 << 10)
)

// SpeedTest downloads url through the tunnel and returns the throughput
// in Mbit/s, timed from the first byte of the body (so connection setup
// does not count). At most speedMaxBytes are read.
func SpeedTest(mark uint32, url string) (float64, error) {
	d := markedDialer(mark, 10*time.Second)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
		DisableCompression:  true,
	}
	cl := &http.Client{Transport: tr, Timeout: speedTimeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "snake-router/1")
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("speed test HTTP %d", resp.StatusCode)
	}
	return measure(resp.Body)
}

// measure reads r (up to speedMaxBytes) and returns its rate in Mbit/s,
// timed from the first byte.
func measure(r io.Reader) (float64, error) {
	buf := make([]byte, 64<<10)
	var n int64
	var start time.Time
	var rerr error
	for n < speedMaxBytes {
		k, err := r.Read(buf)
		if k > 0 {
			if start.IsZero() {
				start = time.Now()
			} else {
				n += int64(k)
			}
		}
		if err != nil {
			if err != io.EOF {
				rerr = err
			}
			break
		}
	}
	el := time.Since(start)
	if n < speedMinBytes {
		if rerr != nil {
			return 0, rerr
		}
		return 0, fmt.Errorf("speed test: only %d bytes", n)
	}
	if el <= 0 {
		el = time.Microsecond
	}
	// A timeout after enough data still gives a usable figure.
	return float64(n) * 8 / el.Seconds() / 1e6, nil
}

// speedDue starts a background speed test of tunnel when one is due, and
// returns the last result.
func (m *Monitor) speedDue(s config.Settings, tunnel string, justHealthy bool) speedState {
	m.mu.Lock()
	defer m.mu.Unlock()
	sp := m.speed[tunnel]
	if sp == nil {
		sp = &speedState{}
		m.speed[tunnel] = sp
	}
	due := sp.checked.IsZero() || justHealthy || sp.force || time.Since(sp.checked) >= time.Duration(s.SpeedTestInterval)*time.Second
	if due && !sp.running && s.SpeedTestURL != "" {
		sp.running, sp.force = true, false
		mark, url, test := s.ProbeMark(tunnel), s.SpeedTestURL, m.speedTest
		go func() {
			m.speedMu.Lock()
			mbps, err := test(mark, url)
			m.speedMu.Unlock()
			m.mu.Lock()
			defer m.mu.Unlock()
			sp.running, sp.checked = false, time.Now()
			if err != nil {
				sp.err = err.Error()
			} else {
				sp.mbps, sp.err = mbps, ""
			}
			if st := m.status[tunnel]; st != nil {
				st.ThroughputMbps, st.SpeedChecked, st.SpeedError, st.SpeedTesting = sp.mbps, sp.checked, sp.err, false
			}
		}()
	}
	return *sp
}

// RecheckSpeed makes the next health check speed test each of tunnels
// that is speed tested, however recent its last measurement. Tunnels
// not measured yet are due anyway; one being tested is left alone.
func (m *Monitor) RecheckSpeed(tunnels []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range tunnels {
		if sp := m.speed[t]; sp != nil && !sp.running {
			sp.force = true
			if st := m.status[t]; st != nil {
				st.SpeedTesting = true
			}
		}
	}
}

// Smoothing of the probe metrics (exponentially weighted).
const (
	rttAlpha  = 0.3
	lossAlpha = 0.1
)

// observe records one probe result: failure count, and the smoothed
// round trip and loss.
func (st *Status) observe(rtt time.Duration, err error) {
	if err != nil {
		st.ProbeFails++
		st.Loss += lossAlpha * (1 - st.Loss)
		return
	}
	st.ProbeFails = 0
	st.ProbeRTT = rtt.Round(time.Millisecond).String()
	ms := float64(rtt) / float64(time.Millisecond)
	if st.RTTMs == 0 {
		st.RTTMs = ms
	} else {
		st.RTTMs += rttAlpha * (ms - st.RTTMs)
	}
	st.Loss -= lossAlpha * st.Loss
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
// geoDue forces an exit-country lookup. speed measures the tunnel's
// throughput in the background when due (Settings.SpeedTestInterval).
func (m *Monitor) Check(s config.Settings, tunnel string, geoDue, speed bool) Status {
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
		st.RTTMs, st.Loss = prev.RTTMs, prev.Loss
	}
	if st.LinkOK {
		rtt, err := probe(s.ProbeMark(tunnel), s.ProbeTargets, 5*time.Second)
		st.everProbed = true
		st.observe(rtt, err)
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
		// A tunnel that went down may come back on another server.
		st.RTTMs, st.Loss = 0, 0
	}
	st.Healthy = st.LinkOK && st.ProbeOK
	if speed && st.Healthy {
		sp := m.speedDue(s, tunnel, !st.geoWasHealthy)
		st.ThroughputMbps, st.SpeedChecked, st.SpeedError, st.SpeedTesting = sp.mbps, sp.checked, sp.err, sp.running
	} else if !st.Healthy {
		m.mu.Lock()
		delete(m.speed, tunnel)
		m.mu.Unlock()
	}
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
	for t, sp := range m.speed {
		if !k[t] && !sp.running {
			delete(m.speed, t)
		}
	}
}
