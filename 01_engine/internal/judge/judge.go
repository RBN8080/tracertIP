// Package judge checks every hop against physics: a location that light in
// fiber could not reach in the measured time is impossible (Katz-Bassett et
// al., IMC 2006; Singla et al., HotNets 2014). Locations are inferences; the
// judge says which it kept, which it rejected and why.
package judge

import (
	"math"
	"net/netip"
	"sort"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// Physics constants (P3), as in 00_verification/analysis/fisica.go.
const (
	earthRadiusKm = 6371.0             // mean radius (IUGG)
	fiberKmPerMs  = 299.792458 / 1.468 // light in fiber: ~204.2 km/ms one way
)

// Coord is a point on Earth in degrees.
type Coord struct{ Lat, Lon float64 }

// DistanceKm is the great-circle distance (haversine).
func DistanceKm(a, b Coord) float64 {
	r := math.Pi / 180
	dLat, dLon := (b.Lat-a.Lat)*r, (b.Lon-a.Lon)*r
	h := math.Pow(math.Sin(dLat/2), 2) + math.Cos(a.Lat*r)*math.Cos(b.Lat*r)*math.Pow(math.Sin(dLon/2), 2)
	return 2 * earthRadiusKm * math.Atan2(math.Sqrt(h), math.Sqrt(1-h))
}

// MinRTTms is the round trip light in fiber needs for a distance.
func MinRTTms(km float64) float64 { return 2 * km / fiberKmPerMs }

// Hop is what the probes saw at one TTL.
type Hop struct {
	TTL     int
	Addrs   []netip.Addr // on-time repliers, most frequent first
	MinRTT  float64      // ms, over on-time replies; <0 = no reply (a gap)
	Sent    int
	Replied int
	Target  bool // the target itself answered (Echo Reply)
}

// Hops summarises probe records per TTL, stopping at the target's TTL.
func Hops(probes []model.Probe, target netip.Addr) []Hop {
	type acc struct {
		h     Hop
		count map[netip.Addr]int
	}
	byTTL := map[int]*acc{}
	targetTTL := 0
	for _, p := range probes {
		a := byTTL[p.TTL]
		if a == nil {
			a = &acc{h: Hop{TTL: p.TTL, MinRTT: -1}, count: map[netip.Addr]int{}}
			byTTL[p.TTL] = a
		}
		a.h.Sent++
		if p.Status == model.StatusReply {
			a.h.Replied++
		}
		for _, r := range p.Replies {
			from, err := netip.ParseAddr(r.From)
			if r.Late || err != nil {
				continue
			}
			a.count[from]++
			if ms := float64(r.RTTNS) / 1e6; a.h.MinRTT < 0 || ms < a.h.MinRTT {
				a.h.MinRTT = ms
			}
			if from == target && (r.ICMPType == 0 || r.ICMPType == 129) { // Echo Reply, ICMP or ICMPv6
				a.h.Target = true
				if targetTTL == 0 || p.TTL < targetTTL {
					targetTTL = p.TTL
				}
			}
		}
	}
	var out []Hop
	for ttl := 1; ; ttl++ {
		a := byTTL[ttl]
		if a == nil || (targetTTL > 0 && ttl > targetTTL) {
			break
		}
		for addr := range a.count {
			a.h.Addrs = append(a.h.Addrs, addr)
		}
		sort.Slice(a.h.Addrs, func(i, j int) bool {
			ci, cj := a.count[a.h.Addrs[i]], a.count[a.h.Addrs[j]]
			return ci > cj || (ci == cj && a.h.Addrs[i].Less(a.h.Addrs[j]))
		})
		out = append(out, a.h)
	}
	return out
}
