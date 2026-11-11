package engine

import (
	"math"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/health"
)

// Candidate is a failover candidate with its verdict.
type Candidate struct {
	Tunnel string `json:"tunnel"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	// Score is the candidate's cost relative to the best measured one
	// (1 = best, 1.5 = 50% worse) under automatic selection; 0 = not
	// scored (priority selection, unusable, or not measured yet).
	Score float64 `json:"score,omitempty"`
}

// Select picks the active tunnel for a policy. since is when current
// became active.
//
// Priority selection (the default):
//   - If the current tunnel is unusable, switch immediately to the
//     highest-priority usable tunnel (or none).
//   - If a higher-priority tunnel is usable again and auto fail-back is on,
//     switch back only after it has been healthy for FailbackHold seconds.
//
// Automatic selection (latency, speed, balanced) ranks the usable tunnels
// by score instead of list order (list order breaks ties, and is used
// while no tunnel has been measured):
//   - If the current tunnel is unusable, switch immediately to the best.
//   - Otherwise switch only when the best is AutoSwitchMargin percent
//     better, has been healthy for FailbackHold seconds, and current has
//     been active for AutoSwitchHold seconds.
func Select(p config.Policy, current string, since time.Time, st map[string]health.Status, s config.Settings, now time.Time) (string, []Candidate) {
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
	if p.AutoSelect() {
		return selectAuto(p, cands, curIdx, best, since, st, s, now)
	}
	if curIdx < 0 || !cands[curIdx].OK {
		return p.Tunnels[best], cands
	}
	if best < curIdx && s.AutoFailback && heldHealthy(st[p.Tunnels[best]], s, now) {
		return p.Tunnels[best], cands
	}
	return current, cands
}

// heldHealthy reports whether a tunnel has been healthy for FailbackHold.
func heldHealthy(h health.Status, s config.Settings, now time.Time) bool {
	return !h.HealthySince.IsZero() && now.Sub(h.HealthySince) >= time.Duration(s.FailbackHold)*time.Second
}

// selectAuto is Select for latency, speed and balanced selection. first is
// the first usable candidate in list order.
func selectAuto(p config.Policy, cands []Candidate, curIdx, first int, since time.Time, st map[string]health.Status, s config.Settings, now time.Time) (string, []Candidate) {
	costs := scores(p.Selection, cands, st)
	best := -1
	for i, c := range costs {
		if c > 0 && (best < 0 || c < costs[best]) {
			best = i
		}
	}
	if best >= 0 {
		for i, c := range costs {
			if c > 0 {
				cands[i].Score = math.Round(c/costs[best]*100) / 100
			}
		}
	}
	if curIdx < 0 || !cands[curIdx].OK {
		if best < 0 {
			return p.Tunnels[first], cands
		}
		return p.Tunnels[best], cands
	}
	cur := p.Tunnels[curIdx]
	if best < 0 || best == curIdx || costs[curIdx] == 0 {
		// Nothing measured to compare against: stay.
		return cur, cands
	}
	better := costs[best] <= costs[curIdx]*(1-float64(s.AutoSwitchMargin)/100)
	settled := since.IsZero() || now.Sub(since) >= time.Duration(s.AutoSwitchHold)*time.Second
	if better && settled && heldHealthy(st[p.Tunnels[best]], s, now) {
		return p.Tunnels[best], cands
	}
	return cur, cands
}

// scores returns each usable candidate's cost under the selection mode
// (lower is better; 0 = unusable or not measured).
//
//   - latency: smoothed probe round trip, divided by the share of probes
//     that succeed;
//   - speed: inverse of the measured throughput;
//   - balanced: latency and throughput relative to the best usable
//     tunnel, multiplied; a tunnel not speed tested yet counts as the
//     best on throughput.
func scores(mode string, cands []Candidate, st map[string]health.Status) []float64 {
	out := make([]float64, len(cands))
	lat := func(h health.Status) float64 {
		if h.RTTMs <= 0 {
			return 0
		}
		return h.RTTMs / (1 - math.Min(h.Loss, 0.9))
	}
	minLat, maxBW := 0.0, 0.0
	for _, c := range cands {
		if !c.OK {
			continue
		}
		h := st[c.Tunnel]
		if l := lat(h); l > 0 && (minLat == 0 || l < minLat) {
			minLat = l
		}
		maxBW = math.Max(maxBW, h.ThroughputMbps)
	}
	for i, c := range cands {
		if !c.OK {
			continue
		}
		h := st[c.Tunnel]
		switch mode {
		case config.SelectLatency:
			out[i] = lat(h)
		case config.SelectSpeed:
			if h.ThroughputMbps > 0 {
				out[i] = 1 / h.ThroughputMbps
			}
		case config.SelectBalanced:
			l := lat(h)
			if l <= 0 {
				continue
			}
			cost := l / minLat
			if h.ThroughputMbps > 0 {
				cost *= maxBW / h.ThroughputMbps
			}
			out[i] = cost
		}
	}
	return out
}
