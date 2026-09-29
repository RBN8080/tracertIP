package enrich

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

// AS is an origin AS answer and the base it came from.
type AS struct {
	ASN     int    `json:"asn"` // 0 = not routed (IPtoASN)
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
	Source  string `json:"source"`
}

// City is a database location for an address.
type City struct {
	City    string  `json:"city"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Source  string  `json:"source"`
}

// dbResult holds what the bases say about one address.
type dbResult struct {
	asn  []AS // IPtoASN first, then DB-IP ASN, then IPinfo if present
	city *City
}

// lookupBases scans each base once and answers only for the wanted
// addresses (binary search per range), so no base is held in memory; this is
// the design of 00_verification/analysis/asn.go.
func lookupBases(dir string, addrs []netip.Addr) (map[netip.Addr]*dbResult, error) {
	keys := slices.Clone(addrs)
	slices.SortFunc(keys, func(a, b netip.Addr) int { return a.Compare(b) })
	keys = slices.Compact(keys)
	out := map[netip.Addr]*dbResult{}
	for _, k := range keys {
		out[k] = &dbResult{}
	}
	each := func(lo, hi netip.Addr, fn func(*dbResult)) {
		i := sort.Search(len(keys), func(i int) bool { return keys[i].Compare(lo) >= 0 })
		for ; i < len(keys) && keys[i].Compare(hi) <= 0; i++ {
			fn(out[keys[i]])
		}
	}
	asn := func(src string) func(ipdb.ASNRange) error {
		return func(r ipdb.ASNRange) error {
			each(r.Lo, r.Hi, func(d *dbResult) {
				d.asn = append(d.asn, AS{ASN: r.ASN, Name: r.Name, Country: r.Country, Source: src})
			})
			return nil
		}
	}
	scans := []struct {
		file string
		read func(io.Reader) error
	}{
		{"ip2asn-v4.tsv.gz", func(r io.Reader) error { _, err := ipdb.ReadIPtoASN(r, asn("iptoasn")); return err }},
		{"ip2asn-v6.tsv.gz", func(r io.Reader) error { _, err := ipdb.ReadIPtoASN(r, asn("iptoasn")); return err }},
		{"dbip-asn-lite.csv.gz", func(r io.Reader) error { _, err := ipdb.ReadDBIPASN(r, asn("dbip-asn")); return err }},
		{"ipinfo_lite.csv.gz", func(r io.Reader) error { _, err := ipdb.ReadIPinfoLite(r, asn("ipinfo")); return err }},
		{"dbip-city-lite.csv.gz", func(r io.Reader) error {
			_, err := ipdb.ReadDBIPCity(r, func(c ipdb.CityRange) error {
				each(c.Lo, c.Hi, func(d *dbResult) {
					d.city = &City{City: c.City, Country: c.Country, Lat: c.Lat, Lon: c.Lon, Source: "dbip-city"}
				})
				return nil
			})
			return err
		}},
	}
	for _, s := range scans {
		err := readGz(filepath.Join(dir, s.file), s.read)
		if errors.Is(err, os.ErrNotExist) {
			continue // an absent base answers nothing; the output says which bases were used
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readGz(path string, fn func(io.Reader) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return err
	}
	defer gz.Close()
	return fn(gz)
}
