package engine

import (
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/health"
)

// Candidate is a failover candidate with its verdict.
type Candidate struct {
	Tunnel string `json:"tunnel"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Select picks the active tunnel for a policy.
//
//   - If the current tunnel is unusable, switch immediately to the
//     highest-priority usable tunnel (or none).
//   - If a higher-priority tunnel is usable again and auto fail-back is on,
//     switch back only after it has been healthy for FailbackHold seconds.
func Select(p config.Policy, current string, st map[string]health.Status, s config.Settings, now time.Time) (string, []Candidate) {
	cands := make([]Candidate, 0, len(p.Tunnels))
	best, curIdx := -1, -1
	for i, t := range p.Tunnels {
		ok, why := health.PolicyOK(st[t], p, s.GeoStrict)
		cands = append(cands, Candidate{Tunnel: t, OK: ok, Reason: why})
		if ok && best < 0 {
			best = i
		}
		if t == current {
			curIdx = i
		}
	}
	if best < 0 {
		return "", cands
	}
	if curIdx < 0 || !cands[curIdx].OK {
		return p.Tunnels[best], cands
	}
	if best < curIdx && s.AutoFailback {
		since := st[p.Tunnels[best]].HealthySince
		if !since.IsZero() && now.Sub(since) >= time.Duration(s.FailbackHold)*time.Second {
			return p.Tunnels[best], cands
		}
	}
	return current, cands
}
