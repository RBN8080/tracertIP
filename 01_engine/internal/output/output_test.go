package output

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/judge"
)

// Public output must not show any address of the home side: the LAN router,
// the CGNAT hops and the access ISP. Addresses come from prefixes because the
// pre-commit checker rejects private host literals.
func TestPublicHidesHome(t *testing.T) {
	first := func(p string) netip.Addr { return netip.MustParsePrefix(p).Addr().Next() }
	lan, cg, isp := first("192.168.0.0/16"), first("100.64.0.0/10"), netip.MustParseAddr("192.0.2.77")
	transit, target := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("203.0.113.9")
	const accessASN = 64496
	hops := []judge.Hop{
		{TTL: 1, Addrs: []netip.Addr{lan}, MinRTT: 0.5},
		{TTL: 2, Addrs: []netip.Addr{cg}, MinRTT: 2},
		{TTL: 3, Addrs: []netip.Addr{isp}, MinRTT: 3},
		{TTL: 4, MinRTT: -1},
		{TTL: 5, Addrs: []netip.Addr{transit}, MinRTT: 35},
		{TTL: 6, Addrs: []netip.Addr{target}, MinRTT: 60, Target: true},
	}
	info := map[netip.Addr]enrich.Info{
		lan:     {Addr: lan.String(), Class: enrich.ClassPrivate},
		cg:      {Addr: cg.String(), Class: enrich.ClassCGNAT},
		isp:     {Addr: isp.String(), Class: enrich.ClassPublic, AS: []enrich.AS{{ASN: accessASN, Name: "HOME-ISP", Source: "iptoasn"}}, Name: "customer-77.example.net"},
		transit: {Addr: transit.String(), Class: enrich.ClassPublic, AS: []enrich.AS{{ASN: 64500, Name: "TRANSIT", Source: "iptoasn"}}},
		target:  {Addr: target.String(), Class: enrich.ClassPublic, AS: []enrich.AS{{ASN: 64501, Name: "DEST", Source: "iptoasn"}}},
	}
	v := judge.Judge(hops, info, nil)

	var table, js bytes.Buffer
	pub := Records(hops, v, info, accessASN, true)
	WriteTable(&table, pub)
	if err := WriteJSON(&js, pub); err != nil {
		t.Fatal(err)
	}
	out := table.String() + js.String()
	for _, secret := range []string{lan.String(), cg.String(), isp.String(), "HOME-ISP", "customer-77", "64496"} {
		if strings.Contains(out, secret) {
			t.Errorf("public output shows %q:\n%s", secret, out)
		}
	}
	for _, shown := range []string{transit.String(), target.String(), "[home]"} {
		if !strings.Contains(out, shown) {
			t.Errorf("public output lacks %q", shown)
		}
	}
	if priv := Records(hops, v, info, accessASN, false); priv[2].Home || priv[2].Info == nil {
		t.Errorf("private output hid hop 3: %+v", priv[2])
	}
}

// A long gain within one metro is not explained by distance, so it gets no
// efficiency (Georgia Tech by IPv6: +44.7 ms over 13 km).
func TestSegmentNote(t *testing.T) {
	rec := func(s judge.Segment) HopRecord {
		return HopRecord{Verdict: judge.Verdict{TTL: 5, Addr: "192.0.2.1", MinRTT: 60, Segment: &s}}
	}
	var b bytes.Buffer
	WriteTable(&b, []HopRecord{
		rec(judge.Segment{FromTTL: 4, Km: 13, NeedMs: 0.13, GainMs: 44.7, Efficiency: 0.003}),
		rec(judge.Segment{FromTTL: 4, Km: 12061, NeedMs: 118.1, GainMs: 132, Efficiency: 0.89}),
	})
	lines := strings.Split(b.String(), "\n")
	if !strings.Contains(lines[1], "within 13 km: not distance") || strings.Contains(lines[1], "efficiency") {
		t.Errorf("same metro: %q", lines[1])
	}
	if !strings.Contains(lines[3], "efficiency 0.89") {
		t.Errorf("ocean jump: %q", lines[3])
	}
}
