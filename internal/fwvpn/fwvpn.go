// Package fwvpn reads the configurations of the firmware's VPN clients
// (Asuswrt-Merlin's wgc1-5 and ovpnc1-5) in the form snake's own saved
// tunnels use, so snake can take them over and run them itself.
//
// WireGuard clients are read from NVRAM (wgc<n>_*). OpenVPN clients are
// read from the configuration the firmware generated when it last started
// the client (/etc/openvpn/client<n>/config.ovpn), with the certificate and
// key files next to it pasted inline.
package fwvpn

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/irisariuan/snake/internal/openvpn"
	"github.com/irisariuan/snake/internal/wireguard"
)

// Kinds of client.
const (
	WireGuard = "wireguard"
	OpenVPN   = "openvpn"
)

// Slots is the number of firmware clients of each kind.
const Slots = 5

// OpenVPNDir is where the firmware keeps a running client's files; %d is
// the client number.
const OpenVPNDir = "/etc/openvpn/client%d"

// Client is one configured firmware VPN client.
type Client struct {
	ID      string `json:"id"`   // wgc1 ... wgc5, ovpnc1 ... ovpnc5
	Kind    string `json:"kind"` // WireGuard or OpenVPN
	Num     int    `json:"num"`
	Name    string `json:"name"`   // the firmware's description
	Server  string `json:"server"` // endpoint or remote, for display
	Enabled bool   `json:"enabled"`
	// Error is why the client cannot be taken over ("" if it can).
	Error string `json:"error,omitempty"`
	// The saved tunnel's content.
	Conf     string `json:"-"`
	Username string `json:"-"`
	Password string `json:"-"`
}

// ParseNVRAM turns `nvram show` output into a map.
func ParseNVRAM(show string) map[string]string {
	kv := map[string]string{}
	for _, l := range strings.Split(show, "\n") {
		if i := strings.IndexByte(l, '='); i > 0 {
			kv[l[:i]] = strings.TrimSpace(l[i+1:])
		}
	}
	return kv
}

// Read lists the configured firmware clients. readFile reads the OpenVPN
// clients' files (os.ReadFile on the router).
func Read(kv map[string]string, readFile func(string) ([]byte, error)) []Client {
	var out []Client
	for n := 1; n <= Slots; n++ {
		if c, ok := readWireGuard(kv, n); ok {
			out = append(out, c)
		}
	}
	for n := 1; n <= Slots; n++ {
		if c, ok := readOpenVPN(kv, n, readFile); ok {
			out = append(out, c)
		}
	}
	return out
}

func readWireGuard(kv map[string]string, n int) (Client, bool) {
	pre := fmt.Sprintf("wgc%d_", n)
	priv, host := kv[pre+"priv"], kv[pre+"ep_addr"]
	if priv == "" && host == "" {
		return Client{}, false // slot not set up
	}
	c := Client{ID: fmt.Sprintf("wgc%d", n), Kind: WireGuard, Num: n, Name: kv[pre+"desc"], Enabled: kv[pre+"enable"] == "1"}
	port := kv[pre+"ep_port"]
	if port == "" {
		port = "51820"
	}
	endpoint := net.JoinHostPort(strings.Trim(host, "[]"), port)
	c.Server = endpoint
	var b strings.Builder
	b.WriteString("[Interface]\nPrivateKey = " + priv + "\n")
	if a := kv[pre+"addr"]; a != "" {
		b.WriteString("Address = " + a + "\n")
	}
	if m, err := strconv.Atoi(kv[pre+"mtu"]); err == nil && m >= 1280 && m <= 9000 {
		fmt.Fprintf(&b, "MTU = %d\n", m)
	}
	b.WriteString("\n[Peer]\nPublicKey = " + kv[pre+"ppub"] + "\n")
	if psk := kv[pre+"psk"]; psk != "" {
		b.WriteString("PresharedKey = " + psk + "\n")
	}
	aips := kv[pre+"aips"]
	if aips == "" {
		aips = "0.0.0.0/0"
	}
	b.WriteString("AllowedIPs = " + aips + "\n")
	b.WriteString("Endpoint = " + endpoint + "\n")
	if ka, err := strconv.Atoi(kv[pre+"alive"]); err == nil && ka > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
	}
	c.Conf = b.String()
	if _, err := wireguard.Parse(c.Conf); err != nil {
		c.Error = "its settings are incomplete: " + err.Error()
	}
	return c, true
}

// Directives whose file argument is pasted inline, and those among them
// that take a key direction after the file.
var (
	inlined   = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true, "extra-certs": true, "crl-verify": true, "dh": true, "secret": true, "pkcs12": true}
	direction = map[string]bool{"tls-auth": true, "secret": true}
)

func readOpenVPN(kv map[string]string, n int, readFile func(string) ([]byte, error)) (Client, bool) {
	pre := fmt.Sprintf("vpn_client%d_", n)
	addr := kv[pre+"addr"]
	dir := fmt.Sprintf(OpenVPNDir, n)
	raw, err := readFile(filepath.Join(dir, "config.ovpn"))
	if addr == "" && err != nil {
		return Client{}, false // slot not set up
	}
	c := Client{ID: fmt.Sprintf("ovpnc%d", n), Kind: OpenVPN, Num: n, Name: kv[pre+"desc"], Server: strings.TrimSpace(addr + " " + kv[pre+"port"]),
		Username: kv[pre+"username"], Password: kv[pre+"password"]}
	st := kv[pre+"state"]
	c.Enabled = (st != "" && st != "0") || kv[pre+"enable"] == "1" || strings.Contains(","+kv["vpn_clientx_eas"]+",", fmt.Sprintf(",%d,", n))
	if err != nil {
		c.Error = "the firmware has not written its configuration (" + filepath.Join(dir, "config.ovpn") + "): start the client once in VPN → VPN Client, then try again"
		return c, true
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], ";") {
			b.WriteString(line + "\n")
			continue
		}
		key := strings.ToLower(strings.TrimPrefix(f[0], "--"))
		switch {
		case key == "auth-user-pass":
			// The firmware's credentials file: "username\npassword".
			if up, err := readFile(resolve(dir, f[1])); err == nil && c.Username == "" {
				lines := strings.SplitN(strings.ReplaceAll(string(up), "\r\n", "\n"), "\n", 3)
				c.Username = strings.TrimSpace(lines[0])
				if len(lines) > 1 {
					c.Password = strings.TrimSpace(lines[1])
				}
			}
			b.WriteString("auth-user-pass\n")
		case inlined[key] && !strings.EqualFold(f[1], "[inline]"):
			data, err := readFile(resolve(dir, f[1]))
			if err != nil {
				c.Error = fmt.Sprintf("cannot read the %s file %s", key, resolve(dir, f[1]))
				return c, true
			}
			fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", key, strings.TrimSpace(string(data)), key)
			if direction[key] && len(f) > 2 {
				b.WriteString("key-direction " + f[2] + "\n")
			}
		default:
			b.WriteString(line + "\n")
		}
	}
	c.Conf = b.String()
	pc, err := openvpn.Parse(c.Conf)
	switch {
	case err != nil:
		c.Error = "its configuration cannot be used: " + err.Error()
	case pc.NeedsAuth && c.Username == "":
		c.Error = "the server asks for a username and password, and none is saved in the firmware"
	}
	if err == nil && len(pc.Remotes) > 0 {
		c.Server = pc.Remotes[0]
	}
	return c, true
}

func resolve(dir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
}
