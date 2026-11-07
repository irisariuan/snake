package openvpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/system"
)

const sample = `# provider file
client
dev tun
proto udp
remote nl1.example.net 1194
remote nl2.example.net 443 tcp
resolv-retry infinite
nobind
persist-key
redirect-gateway def1
dhcp-option DNS 10.8.0.1
up /etc/openvpn/update-resolv-conf
script-security 2
auth-user-pass
cipher AES-256-GCM
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
# not a comment inside a block
-----END CERTIFICATE-----
</ca>
<tls-auth>
KEY
</tls-auth>
`

func TestParseAndRender(t *testing.T) {
	c, err := Parse(strings.ReplaceAll(sample, "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.NeedsAuth || len(c.Remotes) != 2 || c.Remotes[1] != "nl2.example.net 443" {
		t.Fatalf("parsed %+v", c)
	}
	out := c.Render("ovx3", "/tmp/x/ovx3.auth", "/tmp/x/ovx3.pid")
	for _, s := range []string{"remote nl1.example.net 1194", "cipher AES-256-GCM", "# not a comment inside a block", "</tls-auth>",
		"dev ovx3\ndev-type tun", "route-nopull", "script-security 1", "auth-user-pass /tmp/x/ovx3.auth", "writepid /tmp/x/ovx3.pid"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	for _, s := range []string{"dev tun\n", "redirect-gateway def1", "dhcp-option DNS", "update-resolv-conf", "script-security 2", "# provider file"} {
		if strings.Contains(out, s) {
			t.Errorf("kept %q:\n%s", s, out)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for want, text := range map[string]string{
		"paste its contents inline": "client\nremote a.example 1194\nca ca.crt\n",
		"tap":                       "client\nremote a.example 1194\ndev tap0\n",
		"needs a remote":            "client\n",
		"needs a client line":       "remote a.example 1194\n",
		"server configuration":      "server 10.8.0.0 255.255.255.0\nremote a\nclient\n",
		"not closed":                "client\nremote a.example\n<ca>\nX\n",
		"username and password":     "client\nremote a.example\n<auth-user-pass>\nu\np\n</auth-user-pass>\n",
	} {
		if _, err := Parse(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	if _, err := Parse("client\nremote a.example 1194\nca [inline]\n<ca>\nX\n</ca>\n"); err != nil {
		t.Errorf("[inline] rejected: %v", err)
	}
}

func TestManager(t *testing.T) {
	dir := t.TempDir()
	c, err := Parse(sample)
	if err != nil {
		t.Fatal(err)
	}
	alive := map[int]bool{}
	var killed []int
	rec := &system.Recorder{}
	m := &Manager{R: rec, Dir: dir, Owned: func(n string) bool { return strings.HasPrefix(n, "ovx") },
		Alive: func(pid int, _ string) bool { return alive[pid] },
		Kill:  func(pid int) { killed = append(killed, pid); alive[pid] = false }}
	want := []Tunnel{{Name: "ovx1", Conf: c, Username: "me", Password: "secret"}}

	if _, err := m.Sync([]Tunnel{{Name: "ovx1", Conf: c}}); err == nil || !strings.Contains(err.Error(), "username and password") {
		t.Fatalf("missing credentials: %v", err)
	}
	started, err := m.Sync(want)
	if err != nil || len(started) != 1 {
		t.Fatalf("started %v, %v", started, err)
	}
	conf := filepath.Join(dir, "ovx1.conf")
	if !strings.Contains(rec.Joined(), "openvpn --config "+conf+" --daemon snake-ovx1") {
		t.Fatal(rec.Joined())
	}
	if st, err := os.Stat(filepath.Join(dir, "ovx1.auth")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file: %v", err)
	}
	// Running: nothing to do.
	_ = os.WriteFile(filepath.Join(dir, "ovx1.pid"), []byte("4242\n"), 0o644)
	alive[4242] = true
	rec.Commands = nil
	if started, _ := m.Sync(want); len(started) != 0 || len(rec.Commands) != 0 {
		t.Fatalf("restarted a running client: %v", rec.Commands)
	}
	// Exited: restarted, but not more often than RestartDelay.
	alive[4242] = false
	if started, _ := m.Sync(want); len(started) != 0 {
		t.Fatal("restarted within RestartDelay")
	}
	m.lastStart["ovx1"] = time.Now().Add(-RestartDelay)
	if started, _ := m.Sync(want); len(started) != 1 {
		t.Fatal("exited client not restarted")
	}
	// New password: the running client is replaced at once.
	alive[4242] = true
	want[0].Password = "new"
	if started, _ := m.Sync(want); len(started) != 1 || len(killed) != 1 {
		t.Fatalf("not restarted with the new password (killed %v)", killed)
	}
	// No longer needed: stopped, files removed.
	_ = os.WriteFile(filepath.Join(dir, "ovx1.pid"), []byte("4343\n"), 0o644)
	alive[4343] = true
	if _, err := m.Sync(nil); err != nil {
		t.Fatal(err)
	}
	if len(killed) != 2 || killed[1] != 4343 {
		t.Fatalf("killed %v", killed)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("files left: %v", ents)
	}
}
