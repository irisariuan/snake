package engine

import (
	"reflect"
	"testing"

	"github.com/irisariuan/snake/internal/system"
)

func TestWANAddresses(t *testing.T) {
	for _, tc := range []struct {
		primary, secondary string
		want               []string
	}{
		{"198.51.100.20", "203.0.113.10", []string{"198.51.100.20", "203.0.113.10"}},
		{"198.51.100.20", "198.51.100.20", []string{"198.51.100.20"}},
		{"0.0.0.0", "203.0.113.10", []string{"203.0.113.10"}},
		{"invalid", "::", nil},
		{"127.0.0.1", "2001:db8::20", nil},
	} {
		e := New(DefaultPaths(t.TempDir()), &system.Recorder{Responses: map[string]string{
			"nvram get wan0_ipaddr": tc.primary, "nvram get wan1_ipaddr": tc.secondary,
		}})
		if got := e.wanAddrs(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("WAN %q/%q: got %v, want %v", tc.primary, tc.secondary, got, tc.want)
		}
	}
}
