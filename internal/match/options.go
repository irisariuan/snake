package match

import (
	"fmt"
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

// Opts are a session's options.
type Opts struct {
	TTL      time.Duration `json:"ttl,omitempty"` // 0: the global session TTL
	OnLookup bool          `json:"onlookup,omitempty"`
}

// IsZero reports whether no option is set.
func (o Opts) IsZero() bool { return o.TTL == 0 && !o.OnLookup }

// String is the canonical option list ("ttl=10m;onlookup=1").
func (o Opts) String() string {
	var parts []string
	if o.TTL > 0 {
		parts = append(parts, "ttl="+FormatTTL(o.TTL))
	}
	if o.OnLookup {
		parts = append(parts, "onlookup=1")
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
	for _, kv := range strings.Split(text, ";") {
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
		default:
			return o, fmt.Errorf("unknown option %q (ttl, onlookup)", k)
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
