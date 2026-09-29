package targets

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// Shaped like the API on 2026-09-29, with documentation addresses.
const anchorsJSON = `[
 {"id":1,"fqdn":"a.example","ip_v4":"192.0.2.10","as_v4":64500,"ip_v6":"2001:db8::10","as_v6":64500,
  "city":"Town","country":"zz","is_disabled":false,"date_decommissioned":null,
  "geometry":{"type":"Point","coordinates":[-99.1,19.4]}},
 {"id":2,"ip_v4":"192.0.2.20","as_v4":64501,"ip_v6":null,"as_v6":null,"country":"ZZ",
  "is_disabled":true,"date_decommissioned":"2025-06-10T08:15:56","geometry":null}]`

func TestReadAnchors(t *testing.T) {
	a, err := ReadAnchors(strings.NewReader(anchorsJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || !a[0].Active || a[0].Lat != 19.4 || a[0].Lon != -99.1 || a[0].Country != "ZZ" ||
		a[0].IPv6 != netip.MustParseAddr("2001:db8::10") || a[0].ASv6 != 64500 {
		t.Errorf("anchor 1: %+v", a[0])
	}
	if a[1].Active || a[1].IPv6.IsValid() {
		t.Errorf("anchor 2: %+v", a[1])
	}
}

func TestEligible(t *testing.T) {
	all := func(netip.Addr) bool { return true }
	ok := Anchor{ID: 1, Active: true, IPv4: netip.MustParseAddr("192.0.2.1"), IPv6: netip.MustParseAddr("2001:db8::1"),
		ASv4: 64500, ASv6: 64500, Lat: 1, Lon: 1}
	if e, why := Eligible(ok, "EU", all, nil); !e {
		t.Errorf("eligible anchor refused: %s", why)
	}
	v4only := ok
	v4only.IPv6 = netip.Addr{}
	for name, c := range map[string]struct {
		a    Anchor
		cont string
		ex   map[netip.Addr]bool
	}{
		"v4 only":      {v4only, "EU", nil},
		"no continent": {ok, "", nil},
		"excluded":     {ok, "EU", map[netip.Addr]bool{ok.IPv6: true}},
	} {
		if e, _ := Eligible(c.a, c.cont, all, c.ex); e {
			t.Errorf("%s: accepted", name)
		}
	}
}

func cand(id int, country string, as int) Target {
	return Target{Anchor: Anchor{ID: id, Country: country, ASv4: as, ASv6: as}, Continent: "EU"}
}

// Countries take turns, one AS gives one target, failures are kept aside,
// and the same seed gives the same choice.
func TestSelect(t *testing.T) {
	var cs []Target
	for i := range 6 {
		cs = append(cs, cand(100+i, "AA", 64500+i)) // a country with many anchors
	}
	cs = append(cs, cand(200, "BB", 64600), cand(201, "BB", 64600), cand(300, "CC", 64700), cand(301, "CC", 64701))
	bad := map[int]bool{300: true}
	o := Options{Continents: []string{"EU"}, PerContinent: 3, Reserve: 2, Seed: "2026-09-29"}
	verify := func(t *Target) bool { t.Add("test", !bad[t.ID], ""); return !bad[t.ID] }

	chosen, rejected := Select(cs, o, verify)
	if len(chosen) != 5 {
		t.Fatalf("chose %d, want 5", len(chosen))
	}
	per := map[string]int{}
	as := map[int]int{}
	for _, c := range chosen {
		per[c.Country]++
		as[c.ASv4]++
	}
	if per["BB"] != 1 || per["CC"] != 1 || per["AA"] != 3 {
		t.Errorf("per country %v: want BB and CC once each (one AS), AA filling the rest", per)
	}
	for a, n := range as {
		if n > 1 {
			t.Errorf("AS%d chosen %d times", a, n)
		}
	}
	if !slices.ContainsFunc(rejected, func(r Target) bool { return r.ID == 300 && !r.Passed() }) {
		t.Errorf("failed candidate not reported: %+v", rejected)
	}
	roles := ""
	for _, c := range chosen {
		roles += fmt.Sprintf("%s%d ", c.Role, c.Rank)
	}
	if roles != "study1 study2 study3 reserve1 reserve2 " {
		t.Errorf("roles %q", roles)
	}
	again, _ := Select(cs, o, verify)
	if !slices.EqualFunc(chosen, again, func(a, b Target) bool { return a.ID == b.ID }) {
		t.Error("same seed, different choice")
	}
	o.Seed = "another"
	if other, _ := Select(cs, o, verify); slices.EqualFunc(chosen, other, func(a, b Target) bool { return a.ID == b.ID }) {
		t.Log("another seed gave the same choice (possible with few candidates)")
	}
}

func TestPrefixOverview(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sourceapp") != "tracertip" {
			t.Error("request without sourceapp")
		}
		fmt.Fprint(w, `{"status":"ok","data":{"resource":"192.0.2.0/24","announced":true,"asns":[{"asn":64500},{"asn":64501}]}}`)
	}))
	defer srv.Close()
	defer func(u string) { ripestatURL = u }(ripestatURL)
	ripestatURL = srv.URL
	r, err := PrefixOverview(context.Background(), srv.Client(), netip.MustParseAddr("192.0.2.1"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Prefix != "192.0.2.0/24" || !r.Announced || len(r.Origins) != 2 {
		t.Errorf("%+v: want a MOAS prefix with 2 origins", r)
	}
}
