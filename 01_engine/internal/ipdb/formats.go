package ipdb

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// ASNRange maps an IPv4 range to its origin AS. ASN 0 means "not routed".
type ASNRange struct {
	Lo, Hi  netip.Addr
	ASN     int
	Country string
	Name    string
}

// CityRange maps an IPv4 range to a city (DB-IP City Lite).
type CityRange struct {
	Lo, Hi                netip.Addr
	Country, Region, City string
	Lat, Lon              float64
}

// Airport is an IATA code with its coordinates (OurAirports).
type Airport struct {
	IATA, Name, City, Country string
	Lat, Lon                  float64
}

// ReadIPtoASN reads ip2asn-v4.tsv: range_start, range_end, AS_number,
// country_code, AS_description (iptoasn.com, PDDL).
func ReadIPtoASN(r io.Reader, fn func(ASNRange) error) (int, error) {
	cr := csv.NewReader(r)
	cr.Comma, cr.FieldsPerRecord, cr.LazyQuotes, cr.ReuseRecord = '\t', 5, true, true
	return readRows(cr, func(f []string) (bool, error) {
		lo, hi, err := rangeOf(f[0], f[1])
		if err != nil || !lo.Is4() {
			return false, err
		}
		asn, err := strconv.Atoi(f[2])
		if err != nil || asn < 0 {
			return false, fmt.Errorf("bad AS number %q", f[2])
		}
		return true, fn(ASNRange{Lo: lo, Hi: hi, ASN: asn, Country: f[3], Name: f[4]})
	})
}

// ReadDBIPASN reads DB-IP ASN Lite: ip_start, ip_end, asn, name (no header).
func ReadDBIPASN(r io.Reader, fn func(ASNRange) error) (int, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord, cr.ReuseRecord = 4, true
	return readRows(cr, func(f []string) (bool, error) {
		lo, hi, err := rangeOf(f[0], f[1])
		if err != nil || !lo.Is4() {
			return false, err
		}
		asn, err := strconv.Atoi(f[2])
		if err != nil || asn < 0 {
			return false, fmt.Errorf("bad AS number %q", f[2])
		}
		return true, fn(ASNRange{Lo: lo, Hi: hi, ASN: asn, Name: f[3]})
	})
}

// ReadDBIPCity reads DB-IP City Lite: ip_start, ip_end, continent, country,
// region, city, latitude, longitude (no header).
func ReadDBIPCity(r io.Reader, fn func(CityRange) error) (int, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord, cr.ReuseRecord = 8, true
	return readRows(cr, func(f []string) (bool, error) {
		lo, hi, err := rangeOf(f[0], f[1])
		if err != nil || !lo.Is4() {
			return false, err
		}
		lat, lon, err := coords(f[6], f[7])
		if err != nil {
			return false, err
		}
		return true, fn(CityRange{Lo: lo, Hi: hi, Country: f[3], Region: f[4], City: f[5], Lat: lat, Lon: lon})
	})
}

// ReadIPinfoLite reads IPinfo Lite CSV (header: network, ..., asn, as_name, ...).
// A network is a prefix or a single address; an empty asn means no AS.
func ReadIPinfoLite(r io.Reader, fn func(ASNRange) error) (int, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	col, err := header(cr, "network", "country_code", "asn", "as_name")
	if err != nil {
		return 0, err
	}
	return readRows(cr, func(f []string) (bool, error) {
		n := f[col["network"]]
		if strings.Contains(n, ":") || f[col["asn"]] == "" {
			return false, nil
		}
		p, err := netip.ParsePrefix(n)
		if !strings.Contains(n, "/") {
			var a netip.Addr
			if a, err = netip.ParseAddr(n); err == nil {
				p = netip.PrefixFrom(a, 32)
			}
		}
		if err != nil {
			return false, err
		}
		asn, err := strconv.Atoi(strings.TrimPrefix(f[col["asn"]], "AS"))
		if err != nil {
			return false, fmt.Errorf("bad asn %q", f[col["asn"]])
		}
		return true, fn(ASNRange{Lo: p.Masked().Addr(), Hi: lastAddr(p), ASN: asn,
			Country: f[col["country_code"]], Name: f[col["as_name"]]})
	})
}

// ReadAirports reads OurAirports airports.csv, keeping rows with an IATA code.
func ReadAirports(r io.Reader, fn func(Airport) error) (int, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	col, err := header(cr, "name", "latitude_deg", "longitude_deg", "iso_country", "municipality", "iata_code")
	if err != nil {
		return 0, err
	}
	return readRows(cr, func(f []string) (bool, error) {
		iata := f[col["iata_code"]]
		if len(iata) != 3 {
			return false, nil
		}
		lat, lon, err := coords(f[col["latitude_deg"]], f[col["longitude_deg"]])
		if err != nil {
			return false, err
		}
		return true, fn(Airport{IATA: strings.ToLower(iata), Name: f[col["name"]], City: f[col["municipality"]],
			Country: f[col["iso_country"]], Lat: lat, Lon: lon})
	})
}

// readRows reads every record; row returns whether it was kept. A malformed
// row fails the whole file: a partial base is never used (P5).
func readRows(cr *csv.Reader, row func([]string) (bool, error)) (int, error) {
	n := 0
	for {
		f, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		kept, err := row(f)
		if err != nil {
			line, _ := cr.FieldPos(0)
			return n, fmt.Errorf("line %d: %w", line, err)
		}
		if kept {
			n++
		}
	}
}

func header(cr *csv.Reader, need ...string) (map[string]int, error) {
	h, err := cr.Read()
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, c := range h {
		col[c] = i
	}
	for _, c := range need {
		if _, ok := col[c]; !ok {
			return nil, fmt.Errorf("missing column %q", c)
		}
	}
	cr.FieldsPerRecord = len(h)
	return col, nil
}

func rangeOf(a, b string) (netip.Addr, netip.Addr, error) {
	lo, err1 := netip.ParseAddr(a)
	hi, err2 := netip.ParseAddr(b)
	if err := errors.Join(err1, err2); err != nil {
		return lo, hi, err
	}
	if lo.Is4() != hi.Is4() || hi.Less(lo) {
		return lo, hi, fmt.Errorf("bad range %s-%s", a, b)
	}
	return lo, hi, nil
}

func coords(a, b string) (float64, float64, error) {
	lat, err1 := strconv.ParseFloat(a, 64)
	lon, err2 := strconv.ParseFloat(b, 64)
	if err := errors.Join(err1, err2); err != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return 0, 0, fmt.Errorf("bad coordinates %q,%q", a, b)
	}
	return lat, lon, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// AnycastPrefix is a prefix the LACeS census found anycast, and from how many sites.
type AnycastPrefix struct {
	Prefix netip.Prefix
	Sites  int
}

// ReadAnycastCensus reads the LACeS daily census CSV: prefix,
// number_of_sites, backing_prefix (Hendriks et al., IMC 2025).
func ReadAnycastCensus(r io.Reader, fn func(AnycastPrefix) error) (int, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	col, err := header(cr, "prefix", "number_of_sites")
	if err != nil {
		return 0, err
	}
	return readRows(cr, func(f []string) (bool, error) {
		p, err := netip.ParsePrefix(f[col["prefix"]])
		if err != nil || !p.Addr().Is4() {
			return false, err
		}
		n, err := strconv.Atoi(f[col["number_of_sites"]])
		if err != nil || n < 0 {
			return false, fmt.Errorf("bad number_of_sites %q", f[col["number_of_sites"]])
		}
		return true, fn(AnycastPrefix{Prefix: p.Masked(), Sites: n})
	})
}
