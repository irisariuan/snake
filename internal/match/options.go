package match

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Command options: CMD[SETTING=VALUE;SETTING=VALUE;...]:rule
//
//	session[ttl=TIME;onlookup=0|1]:rule
//	route[ttl=TIME;onlookup=0|1]:EXPR;if:EXPR
//
// ttl overrides the session TTL (seconds, or 90s, 10m, 1h). onlookup=1
// counts it from the lookup that started the session (a new lookup renews
// it; connections do not); onlookup=0, the default, counts it from the
// device's last connection to the address.
//
// share=global|GROUP|DEVICE (repeatable: share=A,share=B) also routes the
// session for other devices: every device of the policy (global), the
// members of a device group, or a device (IP address, subnet or MAC).
// Options are separated by ";" or ",".

// Opts are a session's options.
type Opts struct {
	TTL      time.Duration `json:"ttl,omitempty"` // 0: the global session TTL
	OnLookup bool          `json:"onlookup,omitempty"`
	// Share lists who else the session is routed for: "global", a group
	// name, or a device (IP address, subnet, MAC), in the order written.
	Share []string `json:"share,omitempty"`
}

// ShareGlobal shares a session with every device of the policy.
const ShareGlobal = "global"

// IsZero reports whether no option is set.
func (o Opts) IsZero() bool { return o.TTL == 0 && !o.OnLookup && len(o.Share) == 0 }

// String is the canonical option list ("ttl=10m;onlookup=1").
func (o Opts) String() string {
	var parts []string
	if o.TTL > 0 {
		parts = append(parts, "ttl="+FormatTTL(o.TTL))
	}
	if o.OnLookup {
		parts = append(parts, "onlookup=1")
	}
	for _, sh := range o.Share {
		parts = append(parts, "share="+sh)
	}
	return strings.Join(parts, ";")
}

// FormatTTL writes a duration in the shortest whole unit (1h, 10m, 90s).
func FormatTTL(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	case d%time.Minute == 0:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	}
	return strconv.Itoa(int(d.Round(time.Second)/time.Second)) + "s"
}

// splitCmd splits "cmd[opts]:rest" or "cmd:rest" (cmd matched without case).
func splitCmd(s, cmd string) (opts string, hasOpts bool, rest string, ok bool) {
	if len(s) <= len(cmd) || !strings.EqualFold(s[:len(cmd)], cmd) {
		return "", false, "", false
	}
	t := s[len(cmd):]
	switch {
	case strings.HasPrefix(t, ":"):
		return "", false, t[1:], true
	case strings.HasPrefix(t, "["):
		end := strings.Index(t, "]:")
		if end < 0 {
			return "", false, "", false
		}
		return t[1:end], true, t[end+2:], true
	}
	return "", false, "", false
}

// parseOpts parses "ttl=TIME;onlookup=0|1".
func parseOpts(text string) (Opts, error) {
	var o Opts
	seen := map[string]bool{}
	for _, kv := range strings.FieldsFunc(text, func(r rune) bool { return r == ';' || r == ',' }) {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if !ok {
			return o, fmt.Errorf("option %q needs a value (name=value)", kv)
		}
		switch k {
		case "ttl":
			d, err := parseTTL(v)
			if err != nil {
				return o, err
			}
			o.TTL = d
		case "onlookup":
			switch v {
			case "1", "true", "yes", "on":
				o.OnLookup = true
			case "0", "false", "no", "off":
				o.OnLookup = false
			default:
				return o, fmt.Errorf("onlookup must be 0 or 1, not %q", v)
			}
		case "share":
			v, err := normalizeShare(v)
			if err != nil {
				return o, err
			}
			if !seen[v] {
				seen[v] = true
				o.Share = append(o.Share, v)
			}
		default:
			return o, fmt.Errorf("unknown option %q (ttl, onlookup, share)", k)
		}
	}
	return o, nil
}

func parseTTL(v string) (time.Duration, error) {
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if d, err = time.ParseDuration(v); err != nil {
		return 0, fmt.Errorf("ttl %q: seconds or a duration such as 90s, 10m, 1h", v)
	}
	if d < 10*time.Second || d > 7*24*time.Hour {
		return 0, fmt.Errorf("ttl %q must be between 10s and 7 days", v)
	}
	return d, nil
}

// cmdPrefix writes "cmd:" or "cmd[opts]:".
func cmdPrefix(cmd string, o Opts) string {
	if o.IsZero() {
		return cmd + ":"
	}
	return cmd + "[" + o.String() + "]:"
}

// normalizeShare checks a share= value: "global", an IP address, subnet or
// MAC address (canonical form), or a group name (checked by the config).
func normalizeShare(v string) (string, error) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "group:"))
	switch {
	case v == "":
		return "", fmt.Errorf("share needs global, a device group or a device (IP, subnet, MAC)")
	case strings.EqualFold(v, ShareGlobal):
		return ShareGlobal, nil
	}
	if hw, err := net.ParseMAC(v); err == nil && len(hw) == 6 {
		return hw.String(), nil
	}
	if ip := net.ParseIP(v); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
		return ip.String(), nil
	}
	if _, n, err := net.ParseCIDR(v); err == nil {
		return n.String(), nil
	}
	for _, r := range v {
		if !(r == ' ' || r == '_' || r == '.' || r == '-' || r == '+' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return "", fmt.Errorf("share %q is not global, a group name or a device (IP, subnet, MAC)", v)
		}
	}
	return v, nil // group name
}

// ShareDevice reports whether a share= value names a device (not global or a group).
func ShareDevice(v string) bool {
	if _, err := net.ParseMAC(v); err == nil {
		return true
	}
	if net.ParseIP(v) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(v)
	return err == nil
}
