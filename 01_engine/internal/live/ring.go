// Package live runs continuous mode: up to five declared targets probed
// without end, each on its own socket and flow, with their rounds staggered
// (00_IDEA 1.bis and 5). It keeps the last rounds in fixed memory and every
// probe on disk.
package live

import (
	"net/netip"
	"sync"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// Sample is one probe of a round as memory keeps it, without the raw bytes.
type Sample struct {
	TTL    int
	From   netip.Addr // invalid: no reply
	RTTms  float64    // negative: no reply, never 0
	Status string
}

// Round is one round of TTLs to a target. N counts the target's rounds since
// the monitor started; it does not restart with the probe session.
type Round struct {
	Target  netip.Addr
	N       int
	Start   time.Time
	Samples []Sample
}

// Summarize keeps, for each probe, the first reply that came in time.
func Summarize(target netip.Addr, n int, probes []model.Probe) Round {
	r := Round{Target: target, N: n, Samples: make([]Sample, 0, len(probes))}
	for i, p := range probes {
		if i == 0 {
			r.Start = p.SendWall
		}
		s := Sample{TTL: p.TTL, RTTms: -1, Status: p.Status}
		for _, rep := range p.Replies {
			if rep.Late {
				continue
			}
			if a, err := netip.ParseAddr(rep.From); err == nil {
				s.From, s.RTTms = a, float64(rep.RTTNS)/1e6
			}
			break
		}
		r.Samples = append(r.Samples, s)
	}
	return r
}

// Ring keeps the last rounds of one target in fixed memory. Rounds are not
// changed once added, so readers may keep what Last returns.
type Ring struct {
	mu   sync.RWMutex
	buf  []Round
	next int
	full bool
}

// NewRing holds up to n rounds.
func NewRing(n int) *Ring { return &Ring{buf: make([]Round, n)} }

// Add stores r, dropping the oldest round when full.
func (g *Ring) Add(r Round) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.buf[g.next] = r
	g.next = (g.next + 1) % len(g.buf)
	g.full = g.full || g.next == 0
}

// Last returns up to n of the newest rounds, oldest first.
func (g *Ring) Last(n int) []Round {
	g.mu.RLock()
	defer g.mu.RUnlock()
	size := g.next
	if g.full {
		size = len(g.buf)
	}
	n = min(n, size)
	out := make([]Round, 0, n)
	for i := g.next - n; i < g.next; i++ {
		out = append(out, g.buf[(i+len(g.buf))%len(g.buf)])
	}
	return out
}
