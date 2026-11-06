package learn

import (
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func obs(addr, client string, policy int, at time.Duration) Observation {
	return Observation{Addr: addr, Client: client, Policy: policy, Time: t0.Add(at)}
}

func mustCreate(t *testing.T, s *Store, o Observation) int {
	t.Helper()
	if _, out := s.Observe(o, 2*time.Minute); out != NeedGroup {
		t.Fatalf("observe %s: %v, want NeedGroup", o.Addr, out)
	}
	id, err := s.Create(o, "g", []Origin{{PolicyID: o.Policy, ClientIP: o.Client, Trigger: true}})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestBursts(t *testing.T) {
	s, _ := Open("")
	g1 := mustCreate(t, s, obs("203.0.113.1", "192.168.1.10", 1, 0))
	// same device + policy within the window: joins the burst
	if id, out := s.Observe(obs("203.0.113.2", "192.168.1.10", 1, time.Minute), 2*time.Minute); out != Joined || id != g1 {
		t.Fatalf("join: %d %v", id, out)
	}
	// other device: new group
	g2 := mustCreate(t, s, obs("203.0.113.3", "192.168.1.11", 1, time.Minute))
	if g2 == g1 {
		t.Fatal("other device joined the burst")
	}
	// known server: refreshes and re-anchors the burst of that device
	if id, out := s.Observe(obs("203.0.113.1", "192.168.1.11", 1, 90*time.Second), 2*time.Minute); out != Refreshed || id != g1 {
		t.Fatalf("refresh: %d %v", id, out)
	}
	if id, out := s.Observe(obs("203.0.113.4", "192.168.1.11", 1, 100*time.Second), 2*time.Minute); out != Joined || id != g1 {
		t.Fatalf("re-anchored join: %d %v", id, out)
	}
	// window closed: a new burst
	if _, out := s.Observe(obs("203.0.113.5", "192.168.1.10", 1, 10*time.Minute), 2*time.Minute); out != NeedGroup {
		t.Fatalf("after window: %v", out)
	}
	// a live session keeps the burst open
	s.Activity(nil, map[SessionKey]bool{{1, "192.168.1.11"}: true}, t0.Add(30*time.Minute))
	if id, out := s.Observe(obs("203.0.113.6", "192.168.1.11", 1, 31*time.Minute), 2*time.Minute); out != Joined || id != g1 {
		t.Fatalf("session-extended join: %d %v", id, out)
	}
	if r := s.Routes(); r["203.0.113.2"] != 1 || len(r) != 5 {
		t.Fatalf("routes %v", r)
	}
}

func TestExpireFromLastActivity(t *testing.T) {
	s, _ := Open("")
	g := mustCreate(t, s, obs("203.0.113.1", "c", 1, 0))
	s.Observe(obs("203.0.113.2", "c", 1, time.Second), time.Minute)
	ttl := 3600
	// .1 stays in use for 2 hours; .2 goes idle right away
	for m := 0; m <= 120; m += 10 {
		s.Activity(map[string]bool{"203.0.113.1": true}, nil, t0.Add(time.Duration(m)*time.Minute))
		s.Expire(t0.Add(time.Duration(m)*time.Minute), ttl, time.Minute)
	}
	snap := s.Snapshot(ttl)
	if len(snap) != 1 || len(snap[0].Servers) != 1 || snap[0].Servers[0].Addr != "203.0.113.1" {
		t.Fatalf("after 2h: %+v", snap)
	}
	if e := snap[0].Servers[0].ExpiresAt; e == nil || !e.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("expires %v", e)
	}
	// idle for the TTL after the last connection: gone, and the automatic group too
	if !s.Expire(t0.Add(3*time.Hour+time.Second), ttl, time.Minute) {
		t.Fatal("nothing expired")
	}
	if len(s.Snapshot(ttl)) != 0 {
		t.Fatal("empty automatic group kept")
	}
	_ = g
}

func TestPinTTLEditedManual(t *testing.T) {
	s, _ := Open("")
	pinned := mustCreate(t, s, obs("203.0.113.1", "a", 1, 0))
	short := mustCreate(t, s, obs("203.0.113.2", "b", 1, 0))
	named := mustCreate(t, s, obs("203.0.113.3", "c", 1, 0))
	tr, ten, name := true, 600, "Discord"
	if err := s.Update(pinned, Patch{Pinned: &tr}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(short, Patch{TTL: &ten}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(named, Patch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddServers(named, []string{"198.51.100.7"}, t0); err != nil {
		t.Fatal(err)
	}
	s.Expire(t0.Add(11*time.Minute), 86400, time.Minute)
	ids := map[int]Group{}
	for _, g := range s.Snapshot(86400) {
		ids[g.ID] = g
	}
	if _, ok := ids[short]; ok {
		t.Error("group with 10 min TTL survived 11 idle minutes")
	}
	s.Expire(t0.Add(48*time.Hour), 86400, time.Minute)
	ids = map[int]Group{}
	for _, g := range s.Snapshot(86400) {
		ids[g.ID] = g
	}
	if g, ok := ids[pinned]; !ok || len(g.Servers) != 1 || g.Servers[0].ExpiresAt != nil {
		t.Errorf("pinned group: %+v", g)
	}
	// edited group keeps its manual server; the learned one expired
	if g, ok := ids[named]; !ok || g.Name != "Discord" || len(g.Servers) != 1 || g.Servers[0].Addr != "198.51.100.7" {
		t.Errorf("named group: %+v", g)
	}
	bad := 30
	if err := s.Update(named, Patch{TTL: &bad}); err == nil {
		t.Error("ttl 30 accepted")
	}
}

func TestEditMembers(t *testing.T) {
	s, _ := Open("")
	a := mustCreate(t, s, obs("203.0.113.1", "a", 1, 0))
	s.Observe(obs("203.0.113.2", "a", 1, 0), time.Minute)
	b := mustCreate(t, s, obs("203.0.113.3", "b", 2, 0))
	if err := s.AddServers(b, []string{"203.0.113.1"}, t0); err == nil {
		t.Error("address in two groups")
	}
	for _, bad := range []string{"192.168.1.1", "nope", "127.0.0.1", "fe80::1"} {
		if err := s.AddServers(b, []string{bad}, t0); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := s.Move(a, []string{"203.0.113.2"}, b); err != nil {
		t.Fatal(err)
	}
	if r := s.Routes(); r["203.0.113.2"] != 2 {
		t.Fatalf("moved server routes via %d", r["203.0.113.2"])
	}
	off := false
	_ = s.Update(b, Patch{Enabled: &off})
	if r := s.Routes(); r["203.0.113.3"] != 0 {
		t.Fatal("disabled group still routed")
	}
	if err := s.Merge(a, b); err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot(3600)
	if len(snap) != 1 || len(snap[0].Servers) != 3 || len(snap[0].Origins) != 2 {
		t.Fatalf("merged: %+v", snap)
	}
	// bursts of the merged group continue in the target
	if id, out := s.Observe(obs("203.0.113.9", "a", 1, 30*time.Second), time.Minute); out != Joined || id != b {
		t.Fatalf("burst after merge: %d %v", id, out)
	}
	if err := s.RemoveServers(b, []string{"203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Routes()["203.0.113.9"]; ok {
		t.Fatal("removed server still routed")
	}
	if err := s.Delete(b); err != nil || len(s.Routes()) != 0 {
		t.Fatalf("delete: %v %v", err, s.Routes())
	}
}

func TestPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "learnings.json")
	s, err := Open(path)
	if err != nil || !s.IsNew() {
		t.Fatal(err)
	}
	id := mustCreate(t, s, obs("2001:db8:0::5", "c", 3, 0))
	name := "x"
	id2, err := s.New(Patch{Name: &name}, []string{"203.0.113.8"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil || s2.IsNew() {
		t.Fatal(err)
	}
	r := s2.Routes()
	if r["2001:db8::5"] != 3 || r["203.0.113.8"] != 0 {
		t.Fatalf("routes after reload %v", r)
	}
	id3, _ := s2.New(Patch{Name: &name}, nil, t0)
	if id3 <= id || id3 <= id2 {
		t.Fatalf("ids reused: %d %d %d", id, id2, id3)
	}
}
