package openvpn

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/irisariuan/snake/internal/system"
)

// DefaultDir holds the generated configurations, credentials and pid
// files. It is on tmpfs: nothing is written to flash, and a reboot clears
// it (the daemon regenerates it at startup).
const DefaultDir = "/tmp/snake-openvpn"

// RestartDelay is the minimum time between starts of a client that keeps
// exiting (wrong password, unreachable server).
const RestartDelay = 30 * time.Second

// Tunnel is a client to run.
type Tunnel struct {
	Name     string // interface name (ovx1...)
	Conf     *Conf
	Username string
	Password string
}

// Manager starts and stops snake's OpenVPN clients. They run as daemons
// with a pid file, so they keep running across snake restarts and
// updates, like the WireGuard interfaces.
type Manager struct {
	R     system.Runner
	Dir   string
	Owned func(name string) bool
	// Alive and Kill are replaced in tests.
	Alive func(pid int, conf string) bool
	Kill  func(pid int)

	mu        sync.Mutex
	lastStart map[string]time.Time
}

// NewManager returns a manager using DefaultDir.
func NewManager(r system.Runner, owned func(string) bool) *Manager {
	return &Manager{R: r, Dir: DefaultDir, Owned: owned, Alive: procAlive, Kill: func(pid int) { _ = syscall.Kill(pid, syscall.SIGTERM) }}
}

func (m *Manager) path(name, ext string) string { return filepath.Join(m.Dir, name+ext) }

// Sync runs the wanted clients and stops snake's others. It returns the
// clients it started. A client that exited is started again, at most
// once per RestartDelay unless its configuration changed.
func (m *Manager) Sync(want []Tunnel) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastStart == nil {
		m.lastStart = map[string]time.Time{}
	}
	var errs, started []string
	keep := map[string]bool{}
	if len(want) > 0 {
		if err := os.MkdirAll(m.Dir, 0o700); err != nil {
			return nil, fmt.Errorf("openvpn: %v", err)
		}
	}
	for _, t := range want {
		keep[t.Name] = true
		ok, err := m.run(t)
		if err != nil {
			errs = append(errs, fmt.Sprintf("openvpn %s: %v", t.Name, err))
		}
		if ok {
			started = append(started, t.Name)
		}
	}
	for _, n := range m.running() {
		if !keep[n] {
			m.stop(n)
		}
	}
	if len(errs) > 0 {
		return started, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return started, nil
}

// StopAll stops every client snake started.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.running() {
		m.stop(n)
	}
}

func (m *Manager) run(t Tunnel) (bool, error) {
	conf, creds, pid := m.path(t.Name, ".conf"), "", m.path(t.Name, ".pid")
	changed := false
	if t.Username != "" || t.Password != "" {
		creds = m.path(t.Name, ".auth")
		c, err := system.WriteIfChanged(creds, []byte(t.Username+"\n"+t.Password+"\n"), 0o600)
		if err != nil {
			return false, err
		}
		changed = changed || c
	} else if t.Conf.NeedsAuth {
		return false, fmt.Errorf("the server asks for a username and password: enter them")
	}
	c, err := system.WriteIfChanged(conf, []byte(t.Conf.Render(t.Name, creds, pid)), 0o600)
	if err != nil {
		return false, err
	}
	changed = changed || c
	alive := m.pidAlive(t.Name)
	if alive && !changed {
		return false, nil
	}
	if alive {
		m.stop(t.Name) // reconnect with the new configuration
	} else if !changed && time.Since(m.lastStart[t.Name]) < RestartDelay {
		return false, nil
	}
	m.lastStart[t.Name] = time.Now()
	if _, err := m.R.Run("openvpn", "--config", conf, "--daemon", "snake-"+t.Name); err != nil {
		return false, fmt.Errorf("start (see the system log, tag snake-%s): %v", t.Name, err)
	}
	return true, nil
}

func (m *Manager) readPid(name string) int {
	b, err := os.ReadFile(m.path(name, ".pid"))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

func (m *Manager) pidAlive(name string) bool {
	pid := m.readPid(name)
	return pid > 0 && m.Alive(pid, m.path(name, ".conf"))
}

// stop ends a client and removes its files (the credentials too).
func (m *Manager) stop(name string) {
	if pid := m.readPid(name); pid > 0 && m.Alive(pid, m.path(name, ".conf")) {
		m.Kill(pid)
		for i := 0; i < 30 && m.Alive(pid, m.path(name, ".conf")); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	for _, ext := range []string{".pid", ".conf", ".auth"} {
		_ = os.Remove(m.path(name, ext))
	}
	delete(m.lastStart, name)
}

// running lists the clients with files in Dir.
func (m *Manager) running() []string {
	ents, err := os.ReadDir(m.Dir)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range ents {
		n := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if !seen[n] && m.Owned != nil && m.Owned(n) {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// procAlive checks that pid is an openvpn process using conf (a pid can
// be reused by another program after the client exited).
func procAlive(pid int, conf string) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	return err == nil && bytes.Contains(b, []byte(conf))
}
