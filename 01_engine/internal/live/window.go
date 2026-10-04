package live

import (
	"slices"

	"github.com/rbn8080/tracertip/01_engine/internal/stats"
)

// HopWindow is one TTL over a window of rounds (00_IDEA 4, B1). Loss at an
// intermediate hop is usually its ICMP rate limit, not lost traffic (R1).
type HopWindow struct {
	TTL   int    `json:"ttl"`
	Addr  string `json:"addr,omitempty"` // the most frequent replier
	Addrs int    `json:"addrs"`          // distinct repliers: more than one is balancing or a change
	stats.Summary
}

// Window summarises rounds, oldest first, TTL by TTL.
func Window(rounds []Round) []HopWindow {
	byTTL := map[int][]float64{}
	seen := map[int]map[string]int{}
	for _, r := range rounds {
		for _, s := range r.Samples {
			byTTL[s.TTL] = append(byTTL[s.TTL], s.RTTms)
			if s.From.IsValid() {
				if seen[s.TTL] == nil {
					seen[s.TTL] = map[string]int{}
				}
				seen[s.TTL][s.From.String()]++
			}
		}
	}
	ttls := make([]int, 0, len(byTTL))
	for t := range byTTL {
		ttls = append(ttls, t)
	}
	slices.Sort(ttls)
	out := make([]HopWindow, 0, len(ttls))
	for _, t := range ttls {
		w := HopWindow{TTL: t, Addrs: len(seen[t]), Summary: stats.Summarize(byTTL[t])}
		best := 0
		for a, n := range seen[t] {
			if n > best || n == best && a < w.Addr {
				w.Addr, best = a, n
			}
		}
		out = append(out, w)
	}
	return out
}
