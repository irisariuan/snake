package dnsinspect

import (
	"testing"
	"time"
)

func TestRecords(t *testing.T) {
	i := &Inspector{cache: map[string]time.Time{}}
	t0 := time.Now()
	i.mu.Lock()
	i.record(Record{Set: "SNK_1_d4", Addr: "203.0.113.1", Name: "a.example", Rule: "example", LastSeen: t0})
	i.record(Record{Set: "SNK_1_d4", Addr: "203.0.113.1", Name: "b.example", Rule: "example", LastSeen: t0.Add(time.Minute)})
	i.record(Record{Set: "SNK_2_d4", Addr: "203.0.113.1", Name: "c.example", Rule: "c", LastSeen: t0})
	i.cache["SNK_1_d4 203.0.113.1"] = t0.Add(time.Hour)
	i.mu.Unlock()
	r := i.Records("SNK_1_d4")["203.0.113.1"]
	if r.Hits != 2 || !r.FirstSeen.Equal(t0) || r.Name != "b.example" {
		t.Fatalf("%+v", r)
	}
	i.Forget("SNK_1_d4", []string{"203.0.113.1"})
	if len(i.Records("SNK_1_d4")) != 0 || len(i.Records("SNK_2_d4")) != 1 || len(i.cache) != 0 {
		t.Fatal("forget scope")
	}
	i.mu.Lock()
	i.pruneLocked(1)
	i.mu.Unlock()
	if len(i.AllRecords()) != 0 {
		t.Fatal("prune")
	}
}
