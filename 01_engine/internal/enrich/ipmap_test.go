package enrich

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Shaped like a real /locate/all answer (2026-09-29), with public addresses.
const ipmapAnswer = `{"data":{
 "8.8.4.4":{"type":"city","cityNameAscii":"London","countryCodeAlpha2":"GB","latitude":51.5,"longitude":-0.13,
  "contributions":{"worlds":{"score":4},"ixp":{"score":1},"latency":{"score":9.1,"minRtt":0.848,"radius":{"maxDistanceMetres":73749}}}},
 "9.9.9.9":{"type":"city","cityNameAscii":"Tokyo","countryCodeAlpha2":"JP","latitude":35.7,"longitude":139.7,
  "contributions":{"worlds":{"score":4}}},
 "1.1.1.1":null},"metadata":{}}`

func TestParseIPmap(t *testing.T) {
	got, err := parseIPmap(strings.NewReader(ipmapAnswer))
	if err != nil {
		t.Fatal(err)
	}
	m := got[netip.MustParseAddr("8.8.4.4")]
	if m == nil || !m.Measured() || m.City != "London" || m.MinRTT != 0.848 || m.RadiusKm != 73.749 || strings.Join(m.Engines, ",") != "ixp,latency" {
		t.Errorf("8.8.4.4: %+v", m)
	}
	if got[netip.MustParseAddr("9.9.9.9")] != nil {
		t.Error("a city backed only by population was kept")
	}
	if len(got) != 1 {
		t.Errorf("%d answers, want 1", len(got))
	}
}

// The access ISP's addresses never leave the node, and the cache spares a
// second query.
func TestIPmapPrivacyAndCache(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Query().Get("resources"))
		mu.Unlock()
		fmt.Fprint(w, ipmapAnswer)
	}))
	defer srv.Close()
	defer func(u string) { ipmapURL = u }(ipmapURL)
	ipmapURL = srv.URL

	dir := t.TempDir()
	writeGz(t, filepath.Join(dir, "ip2asn-v4.tsv.gz"), "9.9.9.0\t9.9.9.255\t64496\tZZ\tHOME-ISP\n8.8.4.0\t8.8.4.255\t64500\tZZ\tTRANSIT\n")
	o := Options{Dir: dir, NoDNS: true, AccessASN: 64496, IPmapCache: filepath.Join(dir, "cache", "ipmap.json")}
	home, transit := netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("8.8.4.4")
	for range 2 {
		got, err := Enrich(context.Background(), []netip.Addr{home, transit}, o)
		if err != nil {
			t.Fatal(err)
		}
		if got[transit].IPmap == nil || got[home].IPmap != nil {
			t.Errorf("ipmap: transit %+v, home %+v", got[transit].IPmap, got[home].IPmap)
		}
	}
	if len(asked) != 1 || asked[0] != "8.8.4.4" {
		t.Errorf("queries %q, want one query for 8.8.4.4 only", asked)
	}
	if n := len(readIPmapCache(o.IPmapCache)); n != 1 {
		t.Errorf("cache has %d entries", n)
	}
	// Past its lifetime, an entry is asked again.
	lookupIPmap(context.Background(), o.IPmapCache, []netip.Addr{transit}, time.Now().Add(ipmapTTL+time.Hour))
	if len(asked) != 2 {
		t.Errorf("stale cache entry not refreshed: %q", asked)
	}
}
