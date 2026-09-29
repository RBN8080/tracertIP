package enrich

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

func TestClassify(t *testing.T) {
	first := func(p string) netip.Addr { return netip.MustParsePrefix(p).Addr().Next() }
	for a, want := range map[netip.Addr]string{
		first("192.168.0.0/16"):                     ClassPrivate,
		first("100.64.0.0/10"):                      ClassCGNAT, // H8: access hops behind CGNAT
		first("169.254.0.0/16"):                     ClassLink,
		first("192.0.2.0/24"):                       ClassDoc,
		netip.MustParseAddr("8.8.8.8"):              ClassPublic,
		netip.MustParseAddr("100.128.0.1"):          ClassPublic,  // just past 100.64.0.0/10
		first("fc00::/7"):                           ClassPrivate, // IPv6 unique local
		first("fe80::/10"):                          ClassLink,
		netip.MustParseAddr("2001:db8::1"):          ClassDoc,
		netip.MustParseAddr("::1"):                  ClassLoopback,
		netip.MustParseAddr("2001:4860:4860::8888"): ClassPublic,
	} {
		if got, _ := Classify(a); got != want {
			t.Errorf("%s: %s, want %s", a, got, want)
		}
	}
}

// Real hostnames seen on the node on 2026-09-28; airports reduced to a few
// entries, including decoys in other countries.
func testHints() *Hints {
	ap := func(iata, city, cc string, lat, lon float64) ipdb.Airport {
		return ipdb.Airport{IATA: iata, City: city, Country: cc, Lat: lat, Lon: lon}
	}
	return &Hints{
		airports: map[string]ipdb.Airport{
			"syd": ap("syd", "Sydney", "AU", -33.95, 151.18),
			"lax": ap("lax", "Los Angeles", "US", 33.94, -118.41),
			"dfw": ap("dfw", "Dallas-Fort Worth", "US", 32.90, -97.04),
			"anx": ap("anx", "Andenes", "NO", 69.29, 16.14), // decoy: "anx18" in an .au name
			"nsw": ap("nsw", "Decoy", "ZZ", 0, 0),           // decoy: state label "nsw"
			"gin": ap("gin", "Decoy", "ZZ", 0, 0),
			"iad": ap("iad", "Washington", "US", 38.94, -77.46),
			"ash": ap("ash", "Nashua", "US", 42.78, -71.51), // IATA ASH; he.net "ash" is Ashburn
		},
		table: map[string]string{"lsanca": "lax", "dllstx": "dfw", "alxd": "syd", "ash.he.net": "iad"},
	}
}

func TestHints(t *testing.T) {
	h := testHints()
	for name, want := range map[string][]string{
		"dcr02.anx18.syd.au.anexia-it.net":     {"syd"}, // H2
		"ae-13.a04.lsanca07.us.bb.gin.ntt.net": {"lax"},
		"ae-13.r22.dllstx14.us.bb.gin.ntt.net": {"dfw"},
		"et-3-0-2.pe1.alxd.nsw.aarnet.net.au":  {"syd"},
		"core1.lax2.example.com":               {"lax"},
		"100ge0-0-0-2.core4.ash1.he.net":       {"iad"}, // entry scoped to he.net
		"core1.ash1.example.net":               {"ash"}, // other operators keep IATA
		"mirror.aarnet.edu.au":                 nil,
		"customer-192-0-2-88.example.net.mx":   nil,
	} {
		var got []string
		for _, p := range h.For(name) {
			got = append(got, p.IATA)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

// Only a bare IATA guess is weak: a country label or a table entry backs it.
func TestHintWeak(t *testing.T) {
	h := testHints()
	for name, want := range map[string]bool{
		"core1.lax2.example.com":           true,
		"dcr02.anx18.syd.au.anexia-it.net": false,
		"core4.ash1.he.net":                false,
	} {
		if p := h.For(name); len(p) != 1 || p[0].Weak != want {
			t.Errorf("%s: %+v, want weak=%v", name, p, want)
		}
	}
}

func TestHintTableErrors(t *testing.T) {
	h := testHints()
	for _, bad := range []string{"lsanca\tlax\n", "x\tqqq\tsource\n"} {
		if err := h.readTable(strings.NewReader(bad), "t"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBogusPTR(t *testing.T) {
	if !bogusPTR("131.3.250.129.in-addr.arpa.") || bogusPTR("ae-13.a04.lsanca07.us.bb.gin.ntt.net.") {
		t.Error("bogus PTR detection")
	}
}

func writeGz(t *testing.T, path, s string) {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichFromBases(t *testing.T) {
	dir := t.TempDir()
	writeGz(t, filepath.Join(dir, "ip2asn-v4.tsv.gz"),
		"192.0.2.0\t192.0.2.127\t64496\tZZ\tEXAMPLE-A\n198.51.100.0\t198.51.100.255\t0\tNone\tNot routed\n")
	writeGz(t, filepath.Join(dir, "ip2asn-v6.tsv.gz"), "2001:db8:1::\t2001:db8:1:ffff:ffff:ffff:ffff:ffff\t64510\tZZ\tEXAMPLE-V6\n")
	writeGz(t, filepath.Join(dir, "dbip-asn-lite.csv.gz"), "192.0.2.0,192.0.2.255,64497,EXAMPLE-B\n")
	writeGz(t, filepath.Join(dir, "dbip-city-lite.csv.gz"), "192.0.2.0,192.0.2.255,NA,ZZ,R,Town,1.5,2.5\n")

	a, b, c, cg := netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("203.0.114.1"), netip.MustParsePrefix("100.64.0.0/10").Addr().Next()
	// The bases are searched directly: Enrich only looks up public addresses.
	v6 := netip.MustParseAddr("2001:db8:1::42")
	db, err := lookupBases(dir, []netip.Addr{a, b, c, v6}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if as := db[v6].asn; len(as) != 1 || as[0].ASN != 64510 {
		t.Errorf("%s: AS %+v, want 64510 from the IPv6 base", v6, as)
	}
	if as := db[a].asn; len(as) != 2 || as[0].ASN != 64496 || as[0].Source != "iptoasn" || as[1].ASN != 64497 {
		t.Errorf("%s: AS %+v, want IPtoASN 64496 then DB-IP 64497 (both shown)", a, as)
	}
	if db[a].city == nil || db[a].city.City != "Town" {
		t.Errorf("%s: city %+v", a, db[a].city)
	}
	if as := db[b].asn; len(as) != 1 || as[0].ASN != 0 {
		t.Errorf("%s: AS %+v, want AS0 (not routed)", b, as)
	}
	if len(db[c].asn) != 0 {
		t.Errorf("%s: invented an AS %+v", c, db[c].asn)
	}
	got, err := Enrich(context.Background(), []netip.Addr{a, cg}, Options{Dir: dir, NoDNS: true, NoIPmap: true})
	if err != nil {
		t.Fatal(err)
	}
	if got[a].Class != ClassDoc || got[a].AS != nil {
		t.Errorf("%s: %+v, want documentation with no AS", a, got[a])
	}
	if got[cg].Class != ClassCGNAT || got[cg].AS != nil {
		t.Errorf("%s: %+v, want CGNAT with no AS", cg, got[cg])
	}
}
