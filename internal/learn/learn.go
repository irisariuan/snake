// Package learn keeps learning groups: STUN/TURN servers discovered by the
// WebRTC tracker, grouped per discovery burst and independent of policies.
// Each group remembers the sessions that were active when it was discovered
// and is routed through a policy the user can change ("route via").
//
// Servers expire individually once idle: the TTL counts from the later of the
// last STUN request and the last live connection to the server. Groups that
// end up empty are removed unless they are pinned or were edited by the user.
package learn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/irisariuan/snake/internal/system"
)

// Limits.
const (
	MaxOrigins = 20
	MaxServers = 512 // per group
	MaxGroups  = 1000
	MaxTTL     = 2147483
)

// Origin is a policy session that was active when a group was discovered.
type Origin struct {
	Time         time.Time `json:"time"`
	PolicyID     int       `json:"policy_id"`
	Policy       string    `json:"policy"`
	Tunnel       string    `json:"tunnel,omitempty"`
	ClientIP     string    `json:"client_ip"`
	MAC          string    `json:"mac,omitempty"`
	Device       string    `json:"device,omitempty"`
	Destinations []string  `json:"destinations,omitempty"` // policy destinations the device was connected to
	Trigger      bool      `json:"trigger,omitempty"`      // the session whose STUN request was seen
}

// Server is one learned STUN/TURN server address.
type Server struct {
	Addr       string    `json:"addr"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`             // last STUN/TURN request seen
	LastActive time.Time `json:"last_active,omitempty"` // last live connection seen
	Manual     bool      `json:"manual,omitempty"`      // added by hand: never expires
	// ExpiresAt is computed for API views only; nil = never.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Group is a learning group.
type Group struct {
	ID       int       `json:"id"`
	Name     string    `json:"name"`
	Notes    string    `json:"notes,omitempty"`
	Enabled  bool      `json:"enabled"`
	RouteVia int       `json:"route_via"` // policy id; 0 = off (WAN)
	Pinned   bool      `json:"pinned,omitempty"`
	TTL      int       `json:"ttl,omitempty"` // idle seconds; 0 = global default
	Edited   bool      `json:"edited,omitempty"`
	Created  time.Time `json:"created"`
	Origins  []Origin  `json:"origins"`
	Servers  []Server  `json:"servers"`
}

func (s Server) activity() time.Time {
	if s.LastActive.After(s.LastSeen) {
		return s.LastActive
	}
	return s.LastSeen
}

// SessionKey identifies a device's session window with a policy.
type SessionKey struct {
	Policy int
	Client string
}

type burst struct {
	group int
	last  time.Time
}

type fileData struct {
	Version int      `json:"version"`
	NextID  int      `json:"next_id"`
	Groups  []*Group `json:"groups"`
}

// Store holds the groups. It is safe for concurrent use.
type Store struct {
	path string

	mu     sync.Mutex
	data   fileData
	byAddr map[string]*Group
	bursts map[SessionKey]*burst
	dirty  bool
	isNew  bool
}

// Open loads the store from path (a missing file is an empty store).
// An empty path gives an in-memory store.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: fileData{Version: 1, NextID: 1}, bursts: map[SessionKey]*burst{}}
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			s.isNew = true
		case err != nil:
			return nil, err
		default:
			if err := json.Unmarshal(b, &s.data); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		}
	} else {
		s.isNew = true
	}
	if s.data.NextID < 1 {
		s.data.NextID = 1
	}
	for _, g := range s.data.Groups {
		if g.ID >= s.data.NextID {
			s.data.NextID = g.ID + 1
		}
		if g.Origins == nil {
			g.Origins = []Origin{}
		}
		if g.Servers == nil {
			g.Servers = []Server{}
		}
	}
	s.reindex()
	return s, nil
}

// IsNew reports whether no file existed when the store was opened.
func (s *Store) IsNew() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isNew
}

func (s *Store) reindex() {
	s.byAddr = map[string]*Group{}
	for _, g := range s.data.Groups {
		for _, sv := range g.Servers {
			s.byAddr[sv.Addr] = g
		}
	}
}

// Save writes the store if it changed.
func (s *Store) Save() error {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	s.dirty = false
	s.isNew = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = system.WriteIfChanged(s.path, append(b, '\n'), 0o600)
	if err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
	}
	return err
}

// Canon returns the canonical form of an IP address, or "" if invalid.
func Canon(addr string) string {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// ValidServer checks an address that may be added by hand.
func ValidServer(addr string) (string, error) {
	c := Canon(addr)
	if c == "" {
		return "", fmt.Errorf("%q is not an IP address", addr)
	}
	ip := net.ParseIP(c)
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return "", fmt.Errorf("%s is not a public address", c)
	}
	return c, nil
}

func (s *Store) group(id int) *Group {
	for _, g := range s.data.Groups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

// Outcome of an observation.
type Outcome int

const (
	Refreshed Outcome = iota // server already known: timestamps updated
	Joined                   // added to the device's current burst group
	NeedGroup                // unknown and no open burst: call Create
)

// Observation is a STUN/TURN server request seen from a device in a session.
type Observation struct {
	Addr   string
	Client string
	Policy int // policy whose session the request was seen in
	Time   time.Time
}

// Observe records a server request. window is how long a burst stays open
// after the device's last discovery or live session activity.
func (s *Store) Observe(o Observation, window time.Duration) (int, Outcome) {
	addr := Canon(o.Addr)
	key := SessionKey{o.Policy, o.Client}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.byAddr[addr]; g != nil {
		for i := range g.Servers {
			if g.Servers[i].Addr == addr {
				g.Servers[i].LastSeen = o.Time
			}
		}
		s.bursts[key] = &burst{group: g.ID, last: o.Time}
		return g.ID, Refreshed
	}
	if b := s.bursts[key]; b != nil && o.Time.Sub(b.last) <= window {
		if g := s.group(b.group); g != nil && len(g.Servers) < MaxServers {
			g.Servers = append(g.Servers, Server{Addr: addr, FirstSeen: o.Time, LastSeen: o.Time})
			s.byAddr[addr] = g
			b.last = o.Time
			s.dirty = true
			return g.ID, Joined
		}
	}
	return 0, NeedGroup
}

// Create makes a new group for an observation that needs one.
func (s *Store) Create(o Observation, name string, origins []Origin) (int, error) {
	addr := Canon(o.Addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if g := s.byAddr[addr]; g != nil {
		return g.ID, nil
	}
	if len(s.data.Groups) >= MaxGroups {
		return 0, fmt.Errorf("too many learning groups (%d)", MaxGroups)
	}
	if len(origins) > MaxOrigins {
		origins = origins[:MaxOrigins]
	}
	if origins == nil {
		origins = []Origin{}
	}
	g := &Group{ID: s.data.NextID, Name: name, Enabled: true, RouteVia: o.Policy, Created: o.Time,
		Origins: origins, Servers: []Server{{Addr: addr, FirstSeen: o.Time, LastSeen: o.Time}}}
	s.data.NextID++
	s.data.Groups = append(s.data.Groups, g)
	s.byAddr[addr] = g
	s.bursts[SessionKey{o.Policy, o.Client}] = &burst{group: g.ID, last: o.Time}
	s.dirty = true
	return g.ID, nil
}

// Activity applies a conntrack scan: servers with live connections and
// session windows that are still alive (which keep bursts open).
func (s *Store) Activity(active map[string]bool, sessions map[SessionKey]bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for addr := range active {
		g := s.byAddr[addr]
		if g == nil {
			continue
		}
		for i := range g.Servers {
			if g.Servers[i].Addr == addr {
				g.Servers[i].LastActive = now
			}
		}
	}
	for k, b := range s.bursts {
		if sessions[k] {
			b.last = now
		}
	}
}

func ttlOf(g *Group, def int) time.Duration {
	t := g.TTL
	if t <= 0 {
		t = def
	}
	return time.Duration(t) * time.Second
}

// Expire drops idle servers and empty automatic groups. It reports whether
// anything was removed.
func (s *Store) Expire(now time.Time, defTTL int, burstWindow time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	keep := s.data.Groups[:0]
	for _, g := range s.data.Groups {
		if !g.Pinned {
			ttl := ttlOf(g, defTTL)
			sv := g.Servers[:0]
			for _, x := range g.Servers {
				if x.Manual || now.Sub(x.activity()) <= ttl {
					sv = append(sv, x)
				} else {
					changed = true
				}
			}
			g.Servers = sv
		}
		if len(g.Servers) == 0 && !g.Pinned && !g.Edited {
			changed = true
			continue
		}
		keep = append(keep, g)
	}
	s.data.Groups = keep
	for k, b := range s.bursts {
		if now.Sub(b.last) > burstWindow || s.group(b.group) == nil {
			delete(s.bursts, k)
		}
	}
	if changed {
		s.dirty = true
		s.reindex()
	}
	return changed
}

// Routes maps every learned address to its group's routing: the route-via
// policy id, or 0 when the group is disabled or routed nowhere.
func (s *Store) Routes() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.byAddr))
	for addr, g := range s.byAddr {
		if g.Enabled {
			out[addr] = g.RouteVia
		} else {
			out[addr] = 0
		}
	}
	return out
}

// Snapshot returns deep copies of all groups with computed expiry times,
// newest first.
func (s *Store) Snapshot(defTTL int) []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Group, 0, len(s.data.Groups))
	for _, g := range s.data.Groups {
		c := *g
		c.Origins = append([]Origin{}, g.Origins...)
		c.Servers = make([]Server, len(g.Servers))
		ttl := ttlOf(g, defTTL)
		for i, x := range g.Servers {
			if !g.Pinned && !x.Manual {
				t := x.activity().Add(ttl)
				x.ExpiresAt = &t
			}
			c.Servers[i] = x
		}
		out = append(out, c)
	}
	// Newest first; stable while editing.
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// Patch holds editable group fields; nil fields are left unchanged.
type Patch struct {
	Name     *string `json:"name"`
	Notes    *string `json:"notes"`
	Enabled  *bool   `json:"enabled"`
	RouteVia *int    `json:"route_via"`
	Pinned   *bool   `json:"pinned"`
	TTL      *int    `json:"ttl"`
}

func (p Patch) validate() error {
	if p.Name != nil && (strings.TrimSpace(*p.Name) == "" || len(*p.Name) > 100) {
		return errors.New("name must be 1-100 characters")
	}
	if p.Notes != nil && len(*p.Notes) > 4000 {
		return errors.New("notes are limited to 4000 characters")
	}
	if p.TTL != nil && (*p.TTL < 0 || *p.TTL > MaxTTL || (*p.TTL > 0 && *p.TTL < 60)) {
		return fmt.Errorf("ttl must be 0 (default) or 60-%d seconds", MaxTTL)
	}
	if p.RouteVia != nil && *p.RouteVia < 0 {
		return errors.New("route_via must be a policy id or 0")
	}
	return nil
}

func (p Patch) apply(g *Group) {
	if p.Name != nil {
		g.Name = strings.TrimSpace(*p.Name)
		g.Edited = true
	}
	if p.Notes != nil {
		g.Notes = *p.Notes
		g.Edited = true
	}
	if p.Enabled != nil {
		g.Enabled = *p.Enabled
	}
	if p.RouteVia != nil {
		g.RouteVia = *p.RouteVia
	}
	if p.Pinned != nil {
		g.Pinned = *p.Pinned
	}
	if p.TTL != nil {
		g.TTL = *p.TTL
	}
}

// ErrNotFound is returned for unknown group ids.
var ErrNotFound = errors.New("learning group not found")

// New creates a group by hand.
func (s *Store) New(p Patch, servers []string, now time.Time) (int, error) {
	if p.Name == nil {
		return 0, errors.New("name is required")
	}
	if err := p.validate(); err != nil {
		return 0, err
	}
	addrs, err := s.checkAdd(0, servers)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Groups) >= MaxGroups {
		return 0, fmt.Errorf("too many learning groups (%d)", MaxGroups)
	}
	g := &Group{ID: s.data.NextID, Enabled: true, Created: now, Origins: []Origin{}, Servers: []Server{}}
	p.apply(g)
	g.Edited = true
	for _, a := range addrs {
		g.Servers = append(g.Servers, Server{Addr: a, FirstSeen: now, LastSeen: now, Manual: true})
		s.byAddr[a] = g
	}
	s.data.NextID++
	s.data.Groups = append(s.data.Groups, g)
	s.dirty = true
	return g.ID, nil
}

// Update edits a group.
func (s *Store) Update(id int, p Patch) error {
	if err := p.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.group(id)
	if g == nil {
		return ErrNotFound
	}
	p.apply(g)
	s.dirty = true
	return nil
}

// Delete removes a group.
func (s *Store) Delete(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.data.Groups {
		if g.ID == id {
			s.data.Groups = append(s.data.Groups[:i], s.data.Groups[i+1:]...)
			s.reindex()
			s.dirty = true
			return nil
		}
	}
	return ErrNotFound
}

// checkAdd validates addresses to add to group id (0 = a new group).
func (s *Store) checkAdd(id int, servers []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, a := range servers {
		c, err := ValidServer(a)
		if err != nil {
			return nil, err
		}
		if g := s.byAddr[c]; g != nil && g.ID != id {
			return nil, fmt.Errorf("%s is already in group %q (move it instead)", c, g.Name)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// AddServers adds addresses by hand. Manual addresses never expire.
func (s *Store) AddServers(id int, servers []string, now time.Time) error {
	addrs, err := s.checkAdd(id, servers)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.group(id)
	if g == nil {
		return ErrNotFound
	}
	for _, a := range addrs {
		if s.byAddr[a] == g {
			for i := range g.Servers {
				if g.Servers[i].Addr == a {
					g.Servers[i].Manual = true
				}
			}
			continue
		}
		if len(g.Servers) >= MaxServers {
			return fmt.Errorf("a group holds at most %d servers", MaxServers)
		}
		g.Servers = append(g.Servers, Server{Addr: a, FirstSeen: now, LastSeen: now, Manual: true})
		s.byAddr[a] = g
	}
	g.Edited = true
	s.dirty = true
	return nil
}

// RemoveServers removes addresses from a group.
func (s *Store) RemoveServers(id int, servers []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.group(id)
	if g == nil {
		return ErrNotFound
	}
	drop := map[string]bool{}
	for _, a := range servers {
		drop[Canon(a)] = true
	}
	sv := g.Servers[:0]
	for _, x := range g.Servers {
		if !drop[x.Addr] {
			sv = append(sv, x)
		}
	}
	g.Servers = sv
	g.Edited = true
	s.reindex()
	s.dirty = true
	return nil
}

// Move moves addresses (with their history) from one group to another.
func (s *Store) Move(from int, servers []string, to int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, dst := s.group(from), s.group(to)
	if src == nil || dst == nil {
		return ErrNotFound
	}
	if from == to {
		return nil
	}
	mv := map[string]bool{}
	for _, a := range servers {
		mv[Canon(a)] = true
	}
	sv := src.Servers[:0]
	var moved []Server
	for _, x := range src.Servers {
		if mv[x.Addr] {
			moved = append(moved, x)
		} else {
			sv = append(sv, x)
		}
	}
	if len(dst.Servers)+len(moved) > MaxServers {
		return fmt.Errorf("a group holds at most %d servers", MaxServers)
	}
	src.Servers = sv
	dst.Servers = append(dst.Servers, moved...)
	src.Edited, dst.Edited = true, true
	s.reindex()
	s.dirty = true
	return nil
}

// Merge moves everything from group from into group into and deletes from.
func (s *Store) Merge(from, into int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, dst := s.group(from), s.group(into)
	if src == nil || dst == nil {
		return ErrNotFound
	}
	if from == into {
		return errors.New("cannot merge a group into itself")
	}
	if len(dst.Servers)+len(src.Servers) > MaxServers {
		return fmt.Errorf("a group holds at most %d servers", MaxServers)
	}
	dst.Servers = append(dst.Servers, src.Servers...)
	dst.Origins = append(dst.Origins, src.Origins...)
	sort.SliceStable(dst.Origins, func(i, j int) bool { return dst.Origins[i].Time.Before(dst.Origins[j].Time) })
	if len(dst.Origins) > MaxOrigins {
		dst.Origins = dst.Origins[len(dst.Origins)-MaxOrigins:]
	}
	dst.Edited = true
	for i, g := range s.data.Groups {
		if g.ID == from {
			s.data.Groups = append(s.data.Groups[:i], s.data.Groups[i+1:]...)
			break
		}
	}
	for _, b := range s.bursts {
		if b.group == from {
			b.group = into
		}
	}
	s.reindex()
	s.dirty = true
	return nil
}

// Import adds a group of addresses learned before learning groups existed.
func (s *Store) Import(name string, routeVia int, servers []string, now time.Time) {
	addrs, err := s.checkAdd(0, servers)
	if err != nil || len(addrs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := &Group{ID: s.data.NextID, Name: name, Enabled: true, RouteVia: routeVia, Created: now, Origins: []Origin{}, Servers: []Server{}}
	for _, a := range addrs {
		g.Servers = append(g.Servers, Server{Addr: a, FirstSeen: now, LastSeen: now})
		s.byAddr[a] = g
	}
	s.data.NextID++
	s.data.Groups = append(s.data.Groups, g)
	s.dirty = true
}
