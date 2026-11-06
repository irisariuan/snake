package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v1.2.0", "v1.1.9", true},
		{"v1.10.0", "v1.9.3", true},
		{"v2.0.0", "v1.99.99", true},
		{"v1.2.0", "v1.2.0", false},
		{"v1.2.0", "v1.3.0", false},
		{"v1.2.0", "v1.2.0-3-gabc1234", false}, // built after the tag
		{"v1.2.1", "v1.2.0-3-gabc1234-dirty", true},
		{"v1.2.0", "v1.2.0-rc1", true},
		{"v1.2.0", "dev", false},
		{"v1.2.0", "abc1234", false},
		{"nonsense", "v1.0.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func fakeBin(t *testing.T, path, version string) []byte {
	t.Helper()
	b := []byte("#!/bin/sh\necho snake " + version + "\n")
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInstallAndRollback(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "snake")
	fakeBin(t, bin, "v1.0.0")
	newBin := []byte("#!/bin/sh\necho snake v1.1.0\n")
	sum := sha256.Sum256(newBin)
	corrupt := false

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v1.1.0", "body": "notes", "html_url": "https://example/rel",
				"assets": []map[string]string{
					{"name": Asset(), "browser_download_url": srv.URL + "/dl/bin"},
					{"name": SumsAsset, "browser_download_url": srv.URL + "/dl/sums"},
				},
			})
		case "/dl/bin":
			if corrupt {
				_, _ = w.Write([]byte("garbage"))
				return
			}
			_, _ = w.Write(newBin)
		case "/dl/sums":
			_, _ = w.Write([]byte(hex.EncodeToString(sum[:]) + "  " + Asset() + "\nffff  other\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u := &Updater{Bin: bin, Current: "v1.0.0", Repo: func() string { return "o/r" }, APIBase: srv.URL}
	in, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !in.Available || in.Latest != "v1.1.0" || !in.Comparable || in.Previous != "" {
		t.Fatalf("check: %+v", in)
	}

	corrupt = true
	if _, err := u.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt download should fail the checksum: %v", err)
	}
	if v, _ := BinaryVersion(bin); v != "v1.0.0" {
		t.Fatalf("failed install touched the binary: %s", v)
	}
	corrupt = false

	v, err := u.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v != "v1.1.0" {
		t.Fatalf("installed %q", v)
	}
	if got, _ := BinaryVersion(bin); got != "v1.1.0" {
		t.Fatalf("binary is %q", got)
	}
	if u.PreviousVersion() != "v1.0.0" {
		t.Fatalf("previous = %q", u.PreviousVersion())
	}

	v, err = u.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if v != "v1.0.0" {
		t.Fatalf("rolled back to %q", v)
	}
	if got, _ := BinaryVersion(bin); got != "v1.0.0" {
		t.Fatalf("binary after rollback is %q", got)
	}
	// Rolling back again undoes the rollback.
	if u.PreviousVersion() != "v1.1.0" {
		t.Fatalf("previous after rollback = %q", u.PreviousVersion())
	}
}

func TestRollbackWithoutPrevious(t *testing.T) {
	dir := t.TempDir()
	u := &Updater{Bin: filepath.Join(dir, "snake")}
	fakeBin(t, u.Bin, "v1.0.0")
	if _, err := u.Rollback(); err == nil {
		t.Fatal("expected an error")
	}
}
