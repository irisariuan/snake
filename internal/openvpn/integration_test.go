//go:build integration

package openvpn

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/system"
)

// TestIntegrationClient runs snake's client against a real OpenVPN server
// on loopback (run inside `unshare -n`, as root): the provider's
// directives, snake's own and the pushed options must work together, the
// username and password must reach the server, and the client must ignore
// pushed routes.
func TestIntegrationClient(t *testing.T) {
	if os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("set SNAKE_INTEGRATION=1 and run in a network namespace")
	}
	if _, err := exec.LookPath("openvpn"); err != nil {
		t.Skip("openvpn not installed")
	}
	dir := t.TempDir()
	sh := func(cmd string) string {
		t.Helper()
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		return string(out)
	}
	sh("ip link set lo up")
	sh("cd " + dir + ` &&
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=ca -keyout ca.key -out ca.crt 2>/dev/null &&
		openssl req -newkey rsa:2048 -nodes -subj /CN=server -keyout server.key -out server.csr 2>/dev/null &&
		printf 'extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' > ext &&
		openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ext -out server.crt 2>/dev/null &&
		printf '#!/bin/sh\n[ "$(sed -n 1p "$1")" = alice ] && [ "$(sed -n 2p "$1")" = s3cret ]\n' > check.sh && chmod +x check.sh`)
	srv := filepath.Join(dir, "server.conf")
	_ = os.WriteFile(srv, []byte(`port 11940
proto udp
dev srv0
dev-type tun
topology subnet
server 10.99.0.0 255.255.255.0
ca `+dir+`/ca.crt
cert `+dir+`/server.crt
key `+dir+`/server.key
dh none
verify-client-cert none
username-as-common-name
script-security 2
auth-user-pass-verify `+dir+`/check.sh via-file
push "redirect-gateway def1"
push "route 198.51.100.0 255.255.255.0"
push "dhcp-option DNS 10.99.0.1"
keepalive 2 10
writepid `+dir+`/server.pid
log `+dir+`/server.log
`), 0o600)
	sh("openvpn --config " + srv + " --daemon")
	defer func() { _ = exec.Command("sh", "-c", "kill $(cat "+dir+"/server.pid)").Run() }()

	ca, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	// A provider file as handed out: routes, DNS and scripts snake drops.
	c, err := Parse("client\ndev tun\nproto udp\nremote 127.0.0.1 11940\nnobind\nredirect-gateway def1\nup /etc/openvpn/update-resolv-conf\nauth-user-pass\nverb 3\n<ca>\n" + string(ca) + "</ca>\n")
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(system.Exec{}, func(n string) bool { return strings.HasPrefix(n, "ovx") })
	m.Dir = filepath.Join(dir, "client")
	tun := Tunnel{Name: "ovx1", Conf: c, Username: "alice", Password: "s3cret"}
	if _, err := m.Sync([]Tunnel{tun}); err != nil {
		t.Fatal(err)
	}
	defer m.StopAll()
	routes := sh("ip route show table main")
	var addr string
	for i := 0; i < 100 && addr == ""; i++ {
		time.Sleep(100 * time.Millisecond)
		if ifc, err := net.InterfaceByName("ovx1"); err == nil {
			if as, _ := ifc.Addrs(); len(as) > 0 {
				addr = as[0].String()
			}
		}
	}
	if !strings.HasPrefix(addr, "10.99.0.") {
		log, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("ovx1 got no tunnel address (%q); server log:\n%s", addr, log)
	}
	routes = sh("ip route show table main")
	if strings.Contains(routes, "198.51.100.0") || strings.Contains(routes, "0.0.0.0/1") || strings.Contains(routes, "default") {
		t.Fatalf("pushed routes installed:\n%s", routes)
	}
	if !m.pidAlive("ovx1") {
		t.Fatal("client not recognised as running")
	}

	// Stopping removes the interface and the files (credentials included).
	m.StopAll()
	if _, err := net.InterfaceByName("ovx1"); err == nil {
		time.Sleep(time.Second)
	}
	if _, err := net.InterfaceByName("ovx1"); err == nil {
		t.Fatal("ovx1 still exists after stop")
	}
	if ents, _ := os.ReadDir(m.Dir); len(ents) != 0 {
		t.Fatalf("files left after stop: %v", ents)
	}

	// A wrong password is refused by the server: no tunnel address.
	tun.Password = "wrong"
	if _, err := m.Sync([]Tunnel{tun}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if ifc, err := net.InterfaceByName("ovx1"); err == nil {
		if as, _ := ifc.Addrs(); len(as) > 0 {
			t.Fatalf("connected with a wrong password: %v", as)
		}
	}
}
