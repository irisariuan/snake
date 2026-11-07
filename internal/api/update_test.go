package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/update"
)

// Installing an older release on purpose turns automatic updates off:
// the next check would install the latest again.
func TestInstallOlderVersionPinsIt(t *testing.T) {
	var gh *httptest.Server
	gh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tag, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/releases/tags/"); ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "assets": []map[string]string{
				{"name": update.Asset(), "browser_download_url": gh.URL + "/dl/" + tag + "/bin"},
				{"name": update.SumsAsset, "browser_download_url": gh.URL + "/dl/" + tag + "/sums"}}})
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		bin := []byte("#!/bin/sh\necho snake " + parts[2] + "\n")
		if parts[3] == "bin" {
			_, _ = w.Write(bin)
			return
		}
		sum := sha256.Sum256(bin)
		_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  " + update.Asset() + "\n"))
	}))
	defer gh.Close()

	dir := t.TempDir()
	c := config.Default()
	c.Settings.AutoUpdate = true
	c.Settings.PreResolve = false
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.DefaultPaths(dir), &system.Recorder{})
	e.DryRun = true
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "snake")
	_ = os.WriteFile(bin, []byte("#!/bin/sh\necho snake v1.1.0\n"), 0o755)
	s := &Server{E: e, Token: "t", U: &update.Updater{Bin: bin, Current: "v1.1.0", Repo: func() string { return "o/r" }, APIBase: gh.URL}}
	h := s.routes(false)

	post := func(v string) {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/update?version="+v, nil))
		if rr.Code != 200 {
			t.Fatalf("install %s: %d %s", v, rr.Code, rr.Body)
		}
	}
	post("v1.2.0") // newer: automatic updates stay on
	if !e.Config().Settings.AutoUpdate {
		t.Fatal("automatic updates turned off by an upgrade")
	}
	post("v1.0.0")
	if e.Config().Settings.AutoUpdate {
		t.Fatal("automatic updates still on after a downgrade")
	}
	if v, _ := update.BinaryVersion(bin); v != "v1.0.0" {
		t.Fatalf("installed %s", v)
	}
}
