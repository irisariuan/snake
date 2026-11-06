package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

func TestMarkMigrationAndQoSWarning(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":2,"settings":{"mark_mask":1069547520}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &system.Recorder{Responses: map[string]string{"nvram get qos_enable": "1", "nvram get qos_type": "1"}}
	e := New(DefaultPaths(dir), rec)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	e.DetectCaps()
	if !e.Caps().AdaptiveQoS {
		t.Fatal("Adaptive QoS not detected")
	}
	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Version != config.CurrentVersion || saved.Settings.MarkMask != config.DefaultMarkMask || saved.MigratedMarkMask() != 0 {
		t.Fatalf("migration not saved: version %d mask %#x", saved.Version, saved.Settings.MarkMask)
	}

	// The default connection mask is clear of Adaptive QoS.
	if w := e.Warnings(); len(w) != 0 {
		t.Fatalf("warnings %v", w)
	}
	// Putting connection marks back on QoS's bits is pointed out.
	c := e.Config()
	c.Settings.ConnMarkMask = config.DefaultMarkMask
	if err := e.SetConfig(c); err != nil {
		t.Fatal(err)
	}
	if w := e.Warnings(); len(w) != 1 || !strings.Contains(w[0], "Adaptive QoS") {
		t.Fatalf("warnings %v", w)
	}
}
