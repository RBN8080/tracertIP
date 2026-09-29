package judge

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
)

// Candidate is a location someone claims for a hop, with the physics check.
type Candidate struct {
	City     string  `json:"city"`
	Country  string  `json:"country"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Source   string  `json:"source"`            // "ipmap:latency", "name:iata:syd", "name:table:lsanca", "db:dbip-city"
	Km       float64 `json:"km,omitempty"`      // from the origin; hidden in public output
	NeedMs   float64 `json:"need_ms,omitempty"` // likewise: it gives Km away
	Possible bool    `json:"possible"`
	Weak     bool    `json:"weak,omitempty"` // a guess: bare IATA code, or IPmap by population
}

// Segment is the stretch from the previous located hop. Efficiency compares
// the fiber minimum with the measured RTT growth; it is indicative only, as
// the return path is invisible to traceroute.
type Segment struct {
	FromTTL    int     `json:"from_ttl"`
	Km         float64 `json:"km"`
	NeedMs     float64 `json:"need_ms"`
	GainMs     float64 `json:"gain_ms"`
	Efficiency float64 `json:"efficiency"`
}

// Verdict is the judgement of one hop.
type Verdict struct {
	TTL        int         `json:"ttl"`
	Addr       string      `json:"addr,omitempty"`
	MinRTT     float64     `json:"min_rtt_ms"`       // <0: no reply
	MaxKm      float64     `json:"max_km,omitempty"` // physics: at most this far from the origin
	Location   *Candidate  `json:"location,omitempty"`
	Candidates []Candidate `json:"candidates,omitempty"`
	Segment    *Segment    `json:"segment,omitempty"`
	Flags      []string    `json:"flags,omitempty"`
}

// Flags.
const (
	FlagCGNAT        = "cgnat"                // RFC 6598 access hop (H8)
	FlagPrivate      = "private"              // RFC 1918
	FlagIXP          = "ixp"                  // on an exchange's peering LAN
	FlagASChange     = "as-change"            // AS differs from the previous hop
	FlagThirdParty   = "possible-third-party" // A-B-A: lone hop in another AS
	FlagPerPacket    = "per-packet-balancing" // several addresses in one flow
	FlagImpossible   = "impossible-location"  // a claimed location violates physics (H2)
	FlagDBImpossible = "db-location-impossible"
	FlagAnycast      = "possible-anycast" // destination faster than its location allows (H3)
	FlagUnrouted     = "unrouted"         // no AS announces it
	FlagCensus       = "anycast-census"   // the LACeS census lists its prefix as anycast
)

// Judge checks every hop. Without an origin, physics cannot be evaluated and
// no location is kept or rejected (P5: unknown, never zero).
func Judge(hops []Hop, info map[netip.Addr]enrich.Info, origin *Coord) []Verdict {
	out := make([]Verdict, len(hops))
	asOf := make([]int, len(hops)) // 0 = unknown
	lastLocated := -1
	for i, h := range hops {
		v := Verdict{TTL: h.TTL, MinRTT: h.MinRTT}
		if h.MinRTT > 0 {
			v.MaxKm = h.MinRTT / 2 * fiberKmPerMs
		}
		if len(h.Addrs) > 0 {
			a := h.Addrs[0]
			v.Addr = a.String()
			inf := info[a]
			if len(h.Addrs) > 1 {
				v.Flags = append(v.Flags, FlagPerPacket)
			}
			switch inf.Class {
			case enrich.ClassCGNAT:
				v.Flags = append(v.Flags, FlagCGNAT)
			case enrich.ClassPrivate:
				v.Flags = append(v.Flags, FlagPrivate)
			}
			if inf.Anycast != nil {
				v.Flags = append(v.Flags, FlagCensus)
			}
			if inf.IXP != nil {
				v.Flags = append(v.Flags, FlagIXP)
				asOf[i] = inf.IXP.MemberASN
			} else if len(inf.AS) > 0 {
				asOf[i] = inf.AS[0].ASN
				if asOf[i] == 0 {
					v.Flags = append(v.Flags, FlagUnrouted)
				}
			}
			if origin != nil && h.MinRTT >= 0 {
				v.Candidates = candidates(inf, *origin, h.MinRTT)
				v.Location, v.Flags = choose(v.Candidates, h.Target, v.Flags)
			}
		}
		if v.Location != nil {
			if lastLocated >= 0 {
				v.Segment = segment(hops, out, lastLocated, i, v)
			}
			lastLocated = i
		}
		out[i] = v
	}
	markAS(out, asOf)
	return out
}

// candidates lists the claimed locations, strongest first: an IPmap city
// measured from a nearby RIPE Atlas probe (Du et al., CCR 2020), backed name
// hints, IPmap cities backed by a name or an IXP, then guesses (bare IATA
// codes, other IPmap cities) and the base.
func candidates(inf enrich.Info, origin Coord, rtt float64) []Candidate {
	var cs []Candidate
	add := func(c Candidate) {
		c.Km = DistanceKm(origin, Coord{c.Lat, c.Lon})
		c.NeedMs = MinRTTms(c.Km)
		c.Possible = rtt >= c.NeedMs
		cs = append(cs, c)
	}
	m := inf.IPmap
	ipmap := func(ok bool, weak bool) {
		if m == nil || !ok {
			return
		}
		src := "ipmap:" + strings.Join(m.Engines, "+")
		if m.Measured() {
			src = "ipmap:rtt"
		}
		add(Candidate{City: m.City, Country: m.Country, Lat: m.Lat, Lon: m.Lon, Weak: weak, Source: src})
	}
	names := func(weak bool) {
		for _, p := range inf.Places {
			if p.Weak == weak {
				add(Candidate{City: p.City, Country: p.Country, Lat: p.Lat, Lon: p.Lon, Weak: p.Weak,
					Source: fmt.Sprintf("name:%s:%s", p.Source, p.Token)})
			}
		}
	}
	ipmap(m != nil && m.Measured(), false)
	names(false)
	ipmap(m != nil && !m.Measured() && m.Backed(), false)
	names(true)
	ipmap(m != nil && !m.Measured() && !m.Backed(), true)
	if c := inf.DBCity; c != nil {
		add(Candidate{City: c.City, Country: c.Country, Lat: c.Lat, Lon: c.Lon, Source: "db:" + c.Source})
	}
	return cs
}

// choose keeps the first possible candidate. Routers only trust names: bases
// are often wrong for router addresses (Gharaibeh et al., IMC 2017); for the
// target, the base is the usual source (Poese et al., CCR 2011).
func choose(cs []Candidate, target bool, flags []string) (*Candidate, []string) {
	var kept *Candidate
	for i := range cs {
		c := &cs[i]
		fromDB := len(c.Source) > 3 && c.Source[:3] == "db:"
		switch {
		case fromDB && !target:
			// Routers never take the base's city, so its errors say nothing.
		case !c.Possible && c.Weak:
			// A bare three-letter guess that physics rules out is a wrong guess,
			// not a wrong router.
		case !c.Possible && fromDB:
			flags = append(flags, FlagDBImpossible, FlagAnycast)
		case !c.Possible:
			flags = append(flags, FlagImpossible)
		case kept == nil && (!fromDB || target):
			kept = c
		}
	}
	return kept, flags
}

// segment measures the stretch from located hop i to located hop j. Its
// baseline is the lowest RTT among hops i..j-1: a later hop answering faster
// shows an earlier one was slowed by its own ICMP generation, not by distance
// (R2; Steenbergen, NANOG traceroute guide).
func segment(hops []Hop, out []Verdict, i, j int, cur Verdict) *Segment {
	base := -1.0
	for k := i; k < j; k++ {
		if r := hops[k].MinRTT; r >= 0 && (base < 0 || r < base) {
			base = r
		}
	}
	a, b := out[i].Location, cur.Location
	km := DistanceKm(Coord{a.Lat, a.Lon}, Coord{b.Lat, b.Lon})
	s := &Segment{FromTTL: hops[i].TTL, Km: km, NeedMs: MinRTTms(km), GainMs: hops[j].MinRTT - base}
	if s.GainMs > 0 {
		s.Efficiency = s.NeedMs / s.GainMs
	}
	return s
}

// markAS flags AS changes and lone hops in another AS (A-B-A).
func markAS(out []Verdict, asOf []int) {
	prev := -1
	for i := range out {
		if asOf[i] == 0 {
			continue
		}
		if prev >= 0 && asOf[prev] != asOf[i] {
			out[i].Flags = append(out[i].Flags, FlagASChange)
			if next := nextKnown(asOf, i); next >= 0 && asOf[next] == asOf[prev] {
				out[i].Flags = append(out[i].Flags, FlagThirdParty)
			}
		}
		prev = i
	}
}

func nextKnown(asOf []int, i int) int {
	for j := i + 1; j < len(asOf); j++ {
		if asOf[j] != 0 {
			return j
		}
	}
	return -1
}
