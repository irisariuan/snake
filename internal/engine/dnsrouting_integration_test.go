//go:build integration

package engine

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsfwd"
	"github.com/irisariuan/snake/internal/dnsinspect"
	"github.com/irisariuan/snake/internal/dnsmasq"
	"github.com/irisariuan/snake/internal/routing"
	"github.com/irisariuan/snake/internal/system"
)

// Two different VPN exits expose the same resolver IP, but return distinct
// answers. Exercise dnsmasq itself for plain DNS and socket-marked snake
// forwarders for DoT and DoH, not just generated rule strings.
func TestIntegrationSharedDNSResolver(t *testing.T) {
	if os.Getuid() != 0 || os.Getenv("SNAKE_INTEGRATION") == "" {
		t.Skip("requires isolated Linux network namespace")
	}
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		t.Fatal("dnsmasq required for resolver isolation regression")
	}
	sh(t, "ip link set lo up")
	// This fixture has two exits to the same remote address and no WAN
	// default. Reverse-path filtering would reject both replies before the
	// DNS clients see them, independently of the policy routing under test.
	allRP := strings.TrimSpace(sh(t, "sysctl -n net.ipv4.conf.all.rp_filter"))
	defaultRP := strings.TrimSpace(sh(t, "sysctl -n net.ipv4.conf.default.rp_filter"))
	sh(t, "sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0")
	t.Cleanup(func() {
		_ = exec.Command("sysctl", "-qw", "net.ipv4.conf.all.rp_filter="+allRP, "net.ipv4.conf.default.rp_filter="+defaultRP).Run()
	})
	dir := t.TempDir()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certServer.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certServer.Close()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		ns := fmt.Sprintf("snkdns%d", i)
		sh(t, "ip netns add "+ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		sh(t, fmt.Sprintf("ip link del wgc%d 2>/dev/null || true; ip link add wgc%d type veth peer name dnsp%d; ip link set dnsp%d netns %s; ip addr add 10.8%d.0.1/30 dev wgc%d; ip link set wgc%d up", i, i, i, i, ns, i, i, i))
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", fmt.Sprintf("wgc%d", i)).Run() })
		sh(t, fmt.Sprintf("ip netns exec %s sh -c 'ip link set lo up; ip addr add 10.8%d.0.2/30 dev dnsp%d; ip link set dnsp%d up; ip addr add 203.0.113.53/32 dev lo; ip route add default via 10.8%d.0.1'", ns, i, i, i, i))
		ready := filepath.Join(dir, fmt.Sprintf("ready%d", i))
		server := exec.Command("ip", "netns", "exec", ns, "python3", "-c", dnsFixture, certPath, keyPath, fmt.Sprint(i), ready)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Process.Kill()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("DNS fixture did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	s := config.DefaultSettings()
	rm := routing.Manager{R: system.Exec{}}
	probes := []routing.ProbeRoute{{Tunnel: "wgc1", Iface: "wgc1", Up: true}, {Tunnel: "wgc2", Iface: "wgc2", Up: true}}
	if err := rm.Sync(s, []routing.PolicyRoute{
		{ID: 1, Iface: "wgc1", DNSServer: "203.0.113.53", DNSTunnel: "wgc1"},
		{ID: 2, Iface: "wgc2", DNSServer: "203.0.113.53", DNSTunnel: "wgc2"},
	}, probes, false); err != nil {
		t.Fatal(err)
	}
	defer rm.Teardown(false)
	check := func(t *testing.T, server, name, want string) {
		t.Helper()
		answer, err := dnsinspect.Query(server, name, 2*time.Second)
		if err != nil || len(answer.IPs) != 1 || answer.IPs[0].String() != want {
			t.Fatalf("%s via %s: got %+v (%v), want %s", name, server, answer, err, want)
		}
	}
	t.Run("dnsmasq-plain", func(t *testing.T) {
		c := config.Default()
		c.Policies = []config.Policy{
			{ID: 1, Enabled: true, Name: "one", Domains: []string{"one.test"}, Leak: config.Leak{DNSViaTunnel: true, DNSServer: "203.0.113.53"}},
			{ID: 2, Enabled: true, Name: "two", Domains: []string{"two.test"}, Leak: config.Leak{DNSViaTunnel: true, DNSServer: "203.0.113.53"}},
		}
		fragment := dnsmasq.Generate(c, false, map[int]string{1: "203.0.113.53@wgc1", 2: "203.0.113.53@wgc2"})
		conf := "port=10530\nlisten-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\nuser=root\n"
		for _, line := range strings.Split(fragment, "\n") {
			if strings.HasPrefix(line, "server=") {
				conf += line + "\n"
			}
		}
		path := filepath.Join(dir, "dnsmasq.conf")
		if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
		d := exec.Command("dnsmasq", "--no-daemon", "--conf-file="+path, "--pid-file="+filepath.Join(dir, "dnsmasq.pid"))
		if err := d.Start(); err != nil {
			t.Fatal(err)
		}
		defer d.Process.Kill()
		time.Sleep(150 * time.Millisecond)
		check(t, "127.0.0.1:10530", "one.test", "198.18.1.1")
		check(t, "127.0.0.1:10530", "two.test", "198.18.2.1")
	})
	for _, proto := range []string{dnsfwd.DoT, dnsfwd.DoH} {
		t.Run(proto, func(t *testing.T) {
			var m dnsfwd.Manager
			defer m.Stop()
			port := 853
			if proto == dnsfwd.DoH {
				port = 8443
			}
			var specs []dnsfwd.Spec
			for i := 1; i <= 2; i++ {
				specs = append(specs, dnsfwd.Spec{ID: i, Listen: "127.0.0.1:0", Up: dnsfwd.Upstream{Proto: proto, IP: "203.0.113.53", Port: port, TLSName: "example.com", Path: "/dns-query", RootCAs: pool, Mark: s.ProbeMark(fmt.Sprintf("wgc%d", i)), Iface: fmt.Sprintf("wgc%d", i)}})
			}
			if err := m.Configure(specs); err != nil {
				t.Fatal(err)
			}
			for i, stats := range m.Stats() {
				check(t, stats.Listen, "test.example", fmt.Sprintf("198.18.%d.1", i))
			}
			// A failover must discard the old encrypted connection pool,
			// even though the resolver IP and certificate name did not change.
			specs[0].Up.Mark, specs[0].Up.Iface = s.ProbeMark("wgc2"), "wgc2"
			if err := m.Configure(specs); err != nil {
				t.Fatal(err)
			}
			check(t, m.Stats()[1].Listen, "test.example", "198.18.2.1")
			specs[0].Up.Mark, specs[0].Up.Iface = s.ProbeMark("wgc1"), "wgc1"
			if err := m.Configure(specs); err != nil {
				t.Fatal(err)
			}
			// A down tunnel must not fall through to another tunnel or WAN.
			probes[0].Up = false
			sh(t, "ip link set wgc1 down")
			defer exec.Command("ip", "link", "set", "wgc1", "up").Run()
			if err := rm.Sync(s, nil, probes, false); err != nil {
				t.Fatal(err)
			}
			m.Stop()
			if err := m.Configure(specs); err != nil {
				t.Fatal(err)
			}
			if answer, err := dnsinspect.Query(m.Stats()[1].Listen, "test.example", 2*time.Second); err == nil && len(answer.IPs) > 0 {
				t.Fatalf("down tunnel still answered DNS: %v; routes: %s", answer.IPs, sh(t, "ip -4 route show table 1301"))
			}
			probes[0].Up = true
			sh(t, "ip link set wgc1 up")
			if err := rm.Sync(s, nil, probes, false); err != nil {
				t.Fatal(err)
			}
			// Even if another service removes the mark rules, a socket
			// must not use a default route through the other VPN/WAN.
			m.Stop()
			rm.Teardown(false)
			sh(t, "ip route replace default dev wgc2")
			defer exec.Command("ip", "route", "del", "default", "dev", "wgc2").Run()
			if err := m.Configure(specs); err != nil {
				t.Fatal(err)
			}
			// A bound socket may still reach its selected, live interface
			// directly. That is safe; an answer from the other exit is not.
			if answer, err := dnsinspect.Query(m.Stats()[1].Listen, "test.example", 2*time.Second); err == nil {
				for _, ip := range answer.IPs {
					if ip.String() != "198.18.1.1" {
						t.Fatalf("missing rules leaked DNS through the default route: %v", answer.IPs)
					}
				}
			}
			sh(t, "ip route del default dev wgc2")
			if err := rm.Sync(s, nil, probes, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

const dnsFixture = `
import socket, ssl, struct, sys, threading, http.server, pathlib
ip = '203.0.113.53'
ident = int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
def answer(q):
    pos = 12
    while q[pos]: pos += q[pos]+1
    pos += 5
    a = q[pos-4:pos-2] == b'\x00\x01'
    return q[:2]+b'\x81\x80'+q[4:6]+(b'\x00\x01' if a else b'\x00\x00')+b'\x00\x00\x00\x00'+q[12:pos]+(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'+bytes([198,18,ident,1]) if a else b'')
def exact(c,n):
    b = b''
    while len(b)<n:
        v = c.recv(n-len(b))
        if not v: raise EOFError()
        b += v
    return b
def serve(c):
    try:
        c = ctx.wrap_socket(c,server_side=True)
        while True:
            q = exact(c,struct.unpack('!H',exact(c,2))[0]); a = answer(q); c.sendall(struct.pack('!H',len(a))+a)
    except (OSError,EOFError): pass
    finally: c.close()
tcp=socket.socket(); tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); tcp.bind((ip,853)); tcp.listen()
def tlsloop():
    while True:
        c,_=tcp.accept(); threading.Thread(target=serve,args=(c,),daemon=True).start()
threading.Thread(target=tlsloop,daemon=True).start()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        a=answer(self.rfile.read(int(self.headers['Content-Length'])))
        self.send_response(200); self.send_header('Content-Type','application/dns-message'); self.send_header('Content-Length',str(len(a))); self.end_headers(); self.wfile.write(a)
    def log_message(self,*a): pass
h=http.server.HTTPServer((ip,8443),Handler); h.socket=ctx.wrap_socket(h.socket,server_side=True)
threading.Thread(target=h.serve_forever,daemon=True).start()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind((ip,53))
pathlib.Path(sys.argv[4]).touch()
while True:
    q,addr=udp.recvfrom(65535); udp.sendto(answer(q),addr)
`
