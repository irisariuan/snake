package routing

import (
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/system"
)

func TestSyncReconciles(t *testing.T) {
	rec := &system.Recorder{Responses: map[string]string{
		"ip -4 rule show": "0:\tfrom all lookup local\n" +
			"5201:\tfrom all fwmark 0x400000/0x3fc00000 lookup 1001\n" + // keep
			"5209:\tfrom all fwmark 0x2400000/0x3fc00000 lookup 1009\n" + // stale
			"32766:\tfrom all lookup main\n",
	}}
	m := Manager{R: rec}
	s := config.DefaultSettings()
	err := m.Sync(s, []PolicyRoute{
		{ID: 1, Iface: "wgc1", Kill: true, DNSServer: "9.9.9.9"},
		{ID: 2, Iface: "", Kill: true},
		{ID: 3, Iface: "", Kill: false},
	}, []ProbeRoute{{Tunnel: "wgc1", Iface: "wgc1", Up: true}}, false)
	if err != nil {
		t.Fatal(err)
	}
	out := rec.Joined()
	for _, s := range []string{
		"ip -4 route replace default dev wgc1 table 1001",
		"ip -4 route replace unreachable default table 1002",
		"ip -4 route flush table 1003",
		"ip -4 rule add pref 5202 fwmark 0x800000/0x3fc00000 lookup 1002",
		"ip -4 rule add pref 5001 iif lo to 9.9.9.9/32 lookup 1001",
		"ip -4 rule add pref 4981 fwmark 0x3d800000/0x3fc00000 lookup 1301",
		"ip -4 route replace default dev wgc1 table 1301",
		"ip -4 rule del pref 5209 from all fwmark 0x2400000/0x3fc00000 lookup 1009",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	if strings.Contains(out, "rule add pref 5201") {
		t.Error("existing rule re-added")
	}
	if strings.Contains(out, "route flush table 1001") || strings.Contains(out, "route flush table 1002") {
		t.Error("active table flushed (would open a leak window)")
	}
	// adds happen before deletes
	if strings.Index(out, "rule add pref 5202") > strings.Index(out, "rule del pref 5209") {
		t.Error("delete before add")
	}
}
