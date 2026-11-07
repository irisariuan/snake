package engine

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// VPN server clients have no MAC address at the router, so policies
// select them by address. This lists what the router's VPN servers are
// configured with, for the device picker: each WireGuard server peer (its
// tunnel address) and each OpenVPN server's client subnet.

var wgPeerKey = regexp.MustCompile(`^wgs(\d+)_c(\d+)_(enable|name|addr)$`)

// VPNClients lists VPN server clients from NVRAM. Client.MAC holds the
// device entry to use in a policy (an address or subnet).
func (e *Engine) VPNClients() []Client {
	out, err := e.R.Run("nvram", "show")
	if err != nil {
		return nil
	}
	return parseVPNClients(out)
}

func parseVPNClients(show string) []Client {
	kv := map[string]string{}
	for _, l := range strings.Split(show, "\n") {
		if i := strings.IndexByte(l, '='); i > 0 {
			kv[l[:i]] = strings.TrimSpace(l[i+1:])
		}
	}
	type peer struct{ enable, name, addr string }
	peers := map[string]*peer{}
	for k, v := range kv {
		m := wgPeerKey.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		id := m[1] + "/" + m[2]
		p := peers[id]
		if p == nil {
			p = &peer{}
			peers[id] = p
		}
		switch m[3] {
		case "enable":
			p.enable = v
		case "name":
			p.name = v
		case "addr":
			p.addr = v
		}
	}
	var out []Client
	for id, p := range peers {
		if p.enable != "1" || kv["wgs"+strings.SplitN(id, "/", 2)[0]+"_enable"] != "1" {
			continue
		}
		// Peer addresses: "10.6.0.2/32" or "10.6.0.2/32,fd00:6::2/128".
		for _, a := range strings.Split(p.addr, ",") {
			ip := a
			if pf, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil {
				if pf.Bits() != pf.Addr().BitLen() {
					ip = pf.Masked().String()
				} else {
					ip = pf.Addr().String()
				}
			} else if ad, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
				ip = ad.String()
			} else {
				continue
			}
			name := p.name
			if name == "" {
				name = "peer " + strings.SplitN(id, "/", 2)[1]
			}
			out = append(out, Client{MAC: ip, IP: ip, Name: "WireGuard: " + name})
		}
	}
	// OpenVPN servers in tun mode: their client subnet.
	for i := 1; i <= 2; i++ {
		pre := fmt.Sprintf("vpn_server%d_", i)
		if kv[pre+"if"] == "tap" || kv[pre+"sn"] == "" {
			continue
		}
		if st := kv[pre+"state"]; st == "" || st == "0" {
			if !strings.Contains(","+kv["vpn_serverx_start"]+",", fmt.Sprintf(",%d,", i)) {
				continue // not running and not started at boot
			}
		}
		ip, mask := net.ParseIP(kv[pre+"sn"]).To4(), net.ParseIP(kv[pre+"nm"]).To4()
		if ip == nil || mask == nil {
			continue
		}
		ones, _ := net.IPMask(mask).Size()
		n := (&net.IPNet{IP: ip.Mask(net.IPMask(mask)), Mask: net.IPMask(mask)}).String()
		if ones == 0 {
			continue
		}
		out = append(out, Client{MAC: n, IP: n, Name: fmt.Sprintf("OpenVPN server %d clients", i)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].MAC < out[j].Name+out[j].MAC })
	return out
}
