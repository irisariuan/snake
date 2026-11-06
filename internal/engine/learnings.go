package engine

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/learn"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/webrtc"
)

// openLearnings loads the learning store once per process.
func (e *Engine) openLearnings() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.learn != nil {
		return nil
	}
	path := e.P.Learnings
	st, err := learn.Open(path)
	if err != nil {
		bad := path + ".bad"
		logx.Warnf("learnings: %v; moving it to %s and starting empty", err, bad)
		if !e.DryRun {
			_ = os.Rename(path, bad)
		}
		st, _ = learn.Open("")
		if !e.DryRun {
			st, _ = learn.Open(path)
		}
	}
	e.learn = st
	return nil
}

// tracksWebRTC reports whether a policy gets WebRTC tracking (and so a
// server set that learning groups can route through).
func tracksWebRTC(p config.Policy) bool {
	return p.Enabled && p.Leak.WebRTC == config.WebRTCTrack && p.HasDestinations()
}

// importLegacyServers turns server sets learned before learning groups
// existed into one group per policy. Runs once, when no store file exists.
func (e *Engine) importLegacyServers() {
	st := e.learn
	if st == nil || !st.IsNew() {
		return
	}
	cfg := e.runtime()
	ips := e.ipset()
	now := time.Now()
	for _, p := range cfg.Policies {
		var addrs []string
		for _, v6 := range []bool{false, true} {
			for _, m := range ips.Members(netfilter.SetName(p.ID, netfilter.KindServer, v6), 0) {
				addrs = append(addrs, strings.Fields(m)[0])
			}
		}
		if len(addrs) > 0 {
			st.Import("Imported: "+p.Name, p.ID, addrs, now)
			logx.Infof("learnings: imported %d STUN/TURN servers of policy %s", len(addrs), p.Name)
		}
	}
	e.saveLearnings()
}

func (e *Engine) saveLearnings() {
	if e.DryRun || e.learn == nil {
		return
	}
	if err := e.learn.Save(); err != nil {
		logx.Warnf("save learnings: %v", err)
	}
}

// serverRoute is the tracker's packet-path lookup.
func (e *Engine) serverRoute(addr string) (int, bool) {
	m, _ := e.learnRoute.Load().(map[string]int)
	p, ok := m[addr]
	return p, ok
}

// syncLearnings installs the learning groups into the per-policy server
// sets and the tracker's routing table.
func (e *Engine) syncLearnings(cfg *config.Config) error {
	st := e.learn
	if st == nil || cfg == nil {
		return nil
	}
	e.learnMu.Lock()
	defer e.learnMu.Unlock()
	caps := e.Caps()
	usable := map[int]bool{}
	for _, p := range cfg.Policies {
		if tracksWebRTC(p) {
			usable[p.ID] = true
		}
	}
	routes := st.Routes()
	installed := make(map[string]int, len(routes))
	per := map[int][]string{}
	for addr, p := range routes {
		if p != 0 && !usable[p] {
			// Route-via policy is gone, disabled or untracked: leave the
			// server unknown so it follows whatever session it shows up in.
			continue
		}
		installed[addr] = p
		if p != 0 {
			per[p] = append(per[p], addr)
		}
	}
	ips := e.ipset()
	var errs []string
	for id := range usable {
		v4, v6 := netfilter.SplitFamilies(per[id])
		sort.Strings(v4)
		sort.Strings(v6)
		e.replaceIfChanged(ips, netfilter.SetSpec{Name: netfilter.SetName(id, netfilter.KindServer, false), Type: "hash:ip", MaxElem: 65536}, v4, &errs)
		if caps.IPv6 {
			e.replaceIfChanged(ips, netfilter.SetSpec{Name: netfilter.SetName(id, netfilter.KindServer, true), Type: "hash:ip", V6: true, MaxElem: 65536}, v6, &errs)
		}
	}
	e.learnRoute.Store(installed)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (e *Engine) rtCfg() *config.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rt
}

// onServer handles a STUN/TURN server request seen by the tracker.
func (e *Engine) onServer(ev webrtc.ServerEvent) {
	st, cfg := e.learn, e.rtCfg()
	if st == nil || cfg == nil {
		return
	}
	window := time.Duration(cfg.Settings.SessionTimeout) * time.Second
	obs := learn.Observation{Addr: ev.Server, Client: ev.Client, Policy: ev.Policy, Time: ev.Time}
	gid, out := st.Observe(obs, window)
	switch out {
	case learn.Refreshed:
		return
	case learn.Joined:
		logx.Infof("learnings: %s joined group #%d (device %s)", ev.Server, gid, ev.Client)
	case learn.NeedGroup:
		origins := e.gatherOrigins(cfg, ev)
		name := groupName(origins, ev)
		id, err := st.Create(obs, name, origins)
		if err != nil {
			logx.Warnf("learnings: %v", err)
			return
		}
		e.event(policyName(cfg, ev.Policy), "learn", "new learning group %q (#%d): STUN/TURN server %s from %s", name, id, ev.Server, ev.Client)
	}
	if err := e.syncLearnings(cfg); err != nil {
		logx.Warnf("learnings: %v", err)
	}
	e.saveLearnings()
}

// onScan applies a conntrack pass: activity re-arms TTLs, then idle
// servers expire.
func (e *Engine) onScan(sc webrtc.Scan) {
	st, cfg := e.learn, e.rtCfg()
	if st == nil || cfg == nil {
		return
	}
	sess := make(map[learn.SessionKey]bool, len(sc.Sessions))
	for k := range sc.Sessions {
		sess[learn.SessionKey{Policy: k.Policy, Client: k.Client}] = true
	}
	st.Activity(sc.Active, sess, sc.Time)
	window := time.Duration(cfg.Settings.SessionTimeout) * time.Second
	if st.Expire(sc.Time, cfg.Settings.STUNServerTTL, window) {
		if err := e.syncLearnings(cfg); err != nil {
			logx.Warnf("learnings: %v", err)
		}
		e.saveLearnings()
	}
}

func policyName(cfg *config.Config, id int) string {
	for _, p := range cfg.Policies {
		if p.ID == id {
			return p.Name
		}
	}
	return fmt.Sprintf("policy %d", id)
}

// gatherOrigins records the sessions the device had open when a new server
// was discovered: every tracked policy whose session window holds the
// device, with its tunnel, the device and the policy destinations it was
// connected to.
func (e *Engine) gatherOrigins(cfg *config.Config, ev webrtc.ServerEvent) []learn.Origin {
	var mac, dev string
	if !e.DryRun {
		for _, c := range Clients() {
			if c.IP == ev.Client {
				mac, dev = c.MAC, c.Name
			}
		}
	}
	for _, d := range cfg.Devices {
		if mac != "" && d.MAC == mac && d.Name != "" {
			dev = d.Name
		}
	}
	dests := map[int][]string{}
	if f, err := os.Open("/proc/net/nf_conntrack"); err == nil {
		dests = destinationsOf(f, cfg.Settings, ev.Client, ev.Server, e.dns.NameOf)
		f.Close()
	}
	e.mu.Lock()
	active := map[int]string{}
	for k, v := range e.active {
		active[k] = v
	}
	e.mu.Unlock()
	ips := e.ipset()
	var out []learn.Origin
	for _, p := range cfg.Policies {
		if !tracksWebRTC(p) {
			continue
		}
		trig := p.ID == ev.Policy
		if !trig && !ips.Test(netfilter.SetName(p.ID, netfilter.KindSession, ev.V6), ev.Client) {
			continue
		}
		o := learn.Origin{Time: ev.Time, PolicyID: p.ID, Policy: p.Name, Tunnel: active[p.ID], ClientIP: ev.Client,
			MAC: mac, Device: dev, Destinations: dests[p.ID], Trigger: trig}
		if trig {
			out = append([]learn.Origin{o}, out...)
		} else {
			out = append(out, o)
		}
	}
	return out
}

// destinationsOf lists, per policy, up to 5 destinations of the device's
// live policy-marked connections (named via nameOf when known).
func destinationsOf(f *os.File, s config.Settings, client, server string, nameOf func(string) string) map[int][]string {
	out := map[int][]string{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		c, ok := webrtc.ParseConntrack(sc.Text(), s.MarkMask, s.MarkShift())
		if !ok || c.Src != client || c.Dst == server {
			continue
		}
		k := fmt.Sprint(c.ID, " ", c.Dst)
		if seen[k] || len(out[c.ID]) >= 5 {
			continue
		}
		seen[k] = true
		d := c.Dst
		if n := nameOf(c.Dst); n != "" {
			d = n + " (" + c.Dst + ")"
		}
		out[c.ID] = append(out[c.ID], d)
	}
	return out
}

// groupName suggests a name: the policy destination the device was using
// (or the policy), plus the device.
func groupName(origins []learn.Origin, ev webrtc.ServerEvent) string {
	base, dev := "STUN "+ev.Server, ""
	if len(origins) > 0 {
		o := origins[0]
		base = o.Policy
		for _, d := range o.Destinations {
			if i := strings.Index(d, " ("); i > 0 {
				base = d[:i]
				break
			}
		}
		dev = o.Device
		if dev == "" {
			dev = o.ClientIP
		}
	}
	if dev != "" {
		return base + " · " + dev
	}
	return base
}

// Learnings returns all groups and the default idle TTL.
func (e *Engine) Learnings() ([]learn.Group, int) {
	cfg := e.rtCfg()
	ttl := config.DefaultSettings().STUNServerTTL
	if cfg != nil {
		ttl = cfg.Settings.STUNServerTTL
	}
	if e.learn == nil {
		return []learn.Group{}, ttl
	}
	return e.learn.Snapshot(ttl), ttl
}

// EditLearnings runs fn against the store, then installs and saves the
// result. Route-via policy ids are validated against the configuration.
func (e *Engine) EditLearnings(fn func(st *learn.Store) error) error {
	if e.learn == nil {
		return errors.New("learnings are not loaded")
	}
	if err := fn(e.learn); err != nil {
		return err
	}
	if err := e.syncLearnings(e.rtCfg()); err != nil {
		return err
	}
	e.saveLearnings()
	return nil
}

// ValidRouteVia reports whether id is 0 (off) or an existing policy.
func (e *Engine) ValidRouteVia(id int) bool {
	if id == 0 {
		return true
	}
	cfg := e.rtCfg()
	if cfg == nil {
		return false
	}
	for _, p := range cfg.Policies {
		if p.ID == id {
			return true
		}
	}
	return false
}
