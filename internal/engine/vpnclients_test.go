package engine

import (
	"reflect"
	"testing"
)

func TestParseVPNClients(t *testing.T) {
	show := `wgs1_enable=1
wgs1_addr=10.6.0.1/24
wgs1_c1_enable=1
wgs1_c1_name=phone
wgs1_c1_addr=10.6.0.2/32
wgs1_c2_enable=0
wgs1_c2_name=old
wgs1_c2_addr=10.6.0.3/32
wgs1_c3_enable=1
wgs1_c3_addr=10.6.0.4/32,fd00:6::4/128
vpn_server1_sn=10.8.0.0
vpn_server1_nm=255.255.255.0
vpn_server1_if=tun
vpn_server1_state=2
vpn_server2_sn=10.16.0.0
vpn_server2_nm=255.255.255.0
vpn_server2_if=tun
vpn_server2_state=0
vpn_serverx_start=
size: 1234 bytes (5678 left)
`
	got := parseVPNClients(show)
	want := []Client{
		{MAC: "10.8.0.0/24", IP: "10.8.0.0/24", Name: "OpenVPN server 1 clients"},
		{MAC: "10.6.0.4", IP: "10.6.0.4", Name: "WireGuard: peer 3"},
		{MAC: "fd00:6::4", IP: "fd00:6::4", Name: "WireGuard: peer 3"},
		{MAC: "10.6.0.2", IP: "10.6.0.2", Name: "WireGuard: phone"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := parseVPNClients("wgs1_enable=0\nwgs1_c1_enable=1\nwgs1_c1_addr=10.6.0.2/32\n"); len(got) != 0 {
		t.Fatalf("disabled server listed: %+v", got)
	}
}
