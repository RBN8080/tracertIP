package judge

import (
	"math"
	"net/netip"
	"slices"
	"testing"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
)

// Airport coordinates (OurAirports) used as synthetic places.
var (
	dfw = Coord{32.8968, -97.0380}
	lax = Coord{33.9425, -118.4081}
	syd = Coord{-33.9461, 151.1772}
	sjc = Coord{37.3626, -121.9291} // a database answer in California
)

func place(tok string, c Coord, cc string) enrich.Place {
	return enrich.Place{Token: tok, IATA: tok, City: tok, Country: cc, Lat: c.Lat, Lon: c.Lon, Source: "iata"}
}

func TestPhysics(t *testing.T) {
	km := DistanceKm(lax, syd)
	if math.Abs(km-12061) > 10 {
		t.Errorf("LAX-SYD %.0f km, want ~12061", km)
	}
	if need := MinRTTms(km); math.Abs(need-118.1) > 0.2 {
		t.Errorf("LAX-SYD minimum RTT %.1f ms, want ~118.1", need)
	}
}

// The §2 findings, from a synthetic origin in Dallas: H1 ocean jump with its
// efficiency, H2 impossible name, H3 anycast target, H8 CGNAT access.
func TestJudge(t *testing.T) {
	ip := netip.MustParseAddr
	cg := netip.MustParsePrefix("100.64.0.0/10").Addr().Next()
	a1, a2, b, c, d, tgt := ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3"), ip("192.0.2.4"), ip("192.0.2.5"), ip("198.51.100.8")
	hops := []Hop{
		{TTL: 1, Addrs: []netip.Addr{cg}, MinRTT: 2},
		{TTL: 2, Addrs: []netip.Addr{a1, a2}, MinRTT: 40}, // two addresses in one flow
		{TTL: 3, Addrs: []netip.Addr{b}, MinRTT: 38},      // named "syd" at 38 ms: impossible
		{TTL: 4, Addrs: []netip.Addr{c}, MinRTT: 170},     // Sydney, after the ocean
		{TTL: 5, MinRTT: -1},                              // a gap
		{TTL: 6, Addrs: []netip.Addr{d}, MinRTT: 171},
		{TTL: 7, Addrs: []netip.Addr{tgt}, MinRTT: 3, Target: true},
	}
	as := func(n int) []enrich.AS { return []enrich.AS{{ASN: n, Source: "iptoasn"}} }
	info := map[netip.Addr]enrich.Info{
		cg: {Class: enrich.ClassCGNAT},
		a1: {Class: enrich.ClassPublic, AS: as(64500), Places: []enrich.Place{place("lax", lax, "US")}},
		b: {Class: enrich.ClassPublic, AS: as(64501), Places: []enrich.Place{place("syd", syd, "AU")},
			DBCity: &enrich.City{City: "Dallas", Lat: dfw.Lat, Lon: dfw.Lon, Source: "dbip-city"}},
		c:   {Class: enrich.ClassPublic, AS: as(64500), Places: []enrich.Place{place("syd", syd, "AU")}},
		d:   {Class: enrich.ClassPublic, AS: as(64502)},
		tgt: {Class: enrich.ClassPublic, AS: as(64503), DBCity: &enrich.City{City: "San Jose", Lat: sjc.Lat, Lon: sjc.Lon, Source: "dbip-city"}},
	}
	v := Judge(hops, info, &dfw)
	has := func(i int, f string) bool { return slices.Contains(v[i].Flags, f) }

	if !has(0, FlagCGNAT) {
		t.Errorf("H8: hop 1 flags %v", v[0].Flags)
	}
	if !has(1, FlagPerPacket) || v[1].Location == nil || v[1].Location.City != "lax" {
		t.Errorf("hop 2: %+v", v[1])
	}
	if !has(2, FlagImpossible) || v[2].Location != nil {
		t.Errorf("H2: hop 3 kept %+v, flags %v; a router never takes the base's city", v[2].Location, v[2].Flags)
	}
	if !has(2, FlagThirdParty) {
		t.Errorf("hop 3 between two hops of AS64500: flags %v", v[2].Flags)
	}
	s := v[3].Segment
	if s == nil || s.FromTTL != 2 || math.Abs(s.GainMs-132) > 0.01 || math.Abs(s.Efficiency-0.895) > 0.01 {
		t.Errorf("H1: segment %+v, want from TTL 2, 132 ms gain (38 ms baseline), efficiency ~0.89", s)
	}
	if v[4].MinRTT >= 0 || v[4].Addr != "" {
		t.Errorf("gap: %+v", v[4])
	}
	if !has(6, FlagDBImpossible) || !has(6, FlagAnycast) || v[6].Location != nil {
		t.Errorf("H3: target %+v", v[6])
	}
	if got := Judge(hops, info, nil); got[1].Location != nil || got[1].Candidates != nil {
		t.Errorf("without an origin nothing is judged: %+v", got[1])
	}
}

// A city measured by IPmap from a nearby probe outranks a name; an unmeasured
// IPmap answer does not.
func TestIPmapOrder(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	judgeWith := func(m *enrich.IPmap) *Candidate {
		info := map[netip.Addr]enrich.Info{a: {Class: enrich.ClassPublic, IPmap: m,
			Places: []enrich.Place{place("lax", lax, "US")}}}
		return Judge([]Hop{{TTL: 1, Addrs: []netip.Addr{a}, MinRTT: 60}}, info, &dfw)[0].Location
	}
	sj := func(rtt float64, engines ...string) *enrich.IPmap {
		return &enrich.IPmap{City: "San Jose", Country: "US", Lat: sjc.Lat, Lon: sjc.Lon, Engines: engines, MinRTT: rtt}
	}
	if l := judgeWith(sj(0.8, "latency")); l == nil || l.City != "San Jose" || l.Source != "ipmap:rtt" {
		t.Errorf("measured: kept %+v", l)
	}
	if l := judgeWith(sj(0, "reverse-dns")); l == nil || l.City != "lax" {
		t.Errorf("named: kept %+v, want the name hint", l)
	}
	// A probe 8.7 ms away only bounds a disk of ~850 km: the city is a guess.
	info := map[netip.Addr]enrich.Info{a: {Class: enrich.ClassPublic, IPmap: sj(8.7, "latency")}}
	if l := Judge([]Hop{{TTL: 1, Addrs: []netip.Addr{a}, MinRTT: 60}}, info, &dfw)[0].Location; l == nil || !l.Weak {
		t.Errorf("far probe: kept %+v, want a weak guess", l)
	}

	// A guessed place gets no segment, and the next segment starts from the
	// last confident one ("Vienna?" after Jacksonville, 2026-09-29).
	b, c := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	info[b] = enrich.Info{Class: enrich.ClassPublic, Places: []enrich.Place{place("lax", lax, "US")}}
	info[c] = enrich.Info{Class: enrich.ClassPublic, Places: []enrich.Place{place("syd", syd, "AU")}}
	v := Judge([]Hop{{TTL: 1, Addrs: []netip.Addr{b}, MinRTT: 30}, {TTL: 2, Addrs: []netip.Addr{a}, MinRTT: 60},
		{TTL: 3, Addrs: []netip.Addr{c}, MinRTT: 180}}, info, &dfw)
	if v[1].Location == nil || v[1].Segment != nil || v[2].Segment == nil || v[2].Segment.FromTTL != 1 {
		t.Errorf("guess got a segment or broke the chain: %+v / %+v", v[1].Segment, v[2].Segment)
	}
}

// A bare IATA guess that physics rules out is dropped without a flag ("ldn"
// read as Lamidanda, Nepal, for a London router).
func TestWeakGuess(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	guess := place("syd", syd, "AU")
	guess.Weak = true
	v := Judge([]Hop{{TTL: 1, Addrs: []netip.Addr{a}, MinRTT: 10}},
		map[netip.Addr]enrich.Info{a: {Class: enrich.ClassPublic, Places: []enrich.Place{guess}}}, &dfw)
	if v[0].Location != nil || slices.Contains(v[0].Flags, FlagImpossible) {
		t.Errorf("weak guess: %+v", v[0])
	}
}
