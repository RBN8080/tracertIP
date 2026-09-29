package ipdb

import (
	"fmt"
	"io"
	"net/url"
	"time"
)

// Size caps and row floors come from the files seen on 2026-09-28, with a wide
// margin (P3): IPtoASN 7 MB gz, DB-IP ASN 7 MB gz, DB-IP City 86 MB gz,
// OurAirports 12 MB.
const (
	mb  = 1 << 20
	gb  = 1 << 30
	day = 24 * time.Hour // the pace of the daily and monthly sources
)

// Sources are the bases the engine uses. Only IPinfo needs a token, and it
// only serves to measure agreement with IPtoASN (00_IDEA 8).
func Sources() []Source {
	return []Source{
		{
			Name: "iptoasn", File: "ip2asn-v4.tsv.gz", Gzip: true,
			URL: fixed("https://iptoasn.com/data/ip2asn-v4.tsv.gz"), MinAge: time.Hour,
			MaxBytes: 100 * mb, MaxRaw: gb, MinRows: 100_000,
			Validate: func(r io.Reader) (int, error) { return ReadIPtoASN(r, func(ASNRange) error { return nil }) },
		},
		{
			Name: "iptoasn-v6", File: "ip2asn-v6.tsv.gz", Gzip: true,
			URL: fixed("https://iptoasn.com/data/ip2asn-v6.tsv.gz"), MinAge: time.Hour,
			MaxBytes: 100 * mb, MaxRaw: gb, MinRows: 10_000,
			Validate: func(r io.Reader) (int, error) { return ReadIPtoASN(r, func(ASNRange) error { return nil }) },
		},
		{
			Name: "dbip-asn", File: "dbip-asn-lite.csv.gz", Gzip: true, PrevMonth: true,
			URL: monthly("https://download.db-ip.com/free/dbip-asn-lite-%s.csv.gz"), MinAge: day,
			MaxBytes: 100 * mb, MaxRaw: gb, MinRows: 100_000,
			Validate: func(r io.Reader) (int, error) { return ReadDBIPASN(r, func(ASNRange) error { return nil }) },
		},
		{
			Name: "dbip-city", File: "dbip-city-lite.csv.gz", Gzip: true, PrevMonth: true,
			URL: monthly("https://download.db-ip.com/free/dbip-city-lite-%s.csv.gz"), MinAge: day,
			MaxBytes: gb, MaxRaw: 4 * gb, MinRows: 1_000_000,
			Validate: func(r io.Reader) (int, error) { return ReadDBIPCity(r, func(CityRange) error { return nil }) },
		},
		{
			Name: "ourairports", File: "airports.csv",
			URL: fixed("https://davidmegginson.github.io/ourairports-data/airports.csv"), MinAge: day,
			MaxBytes: 200 * mb, MaxRaw: 200 * mb, MinRows: 5_000,
			Validate: func(r io.Reader) (int, error) { return ReadAirports(r, func(Airport) error { return nil }) },
		},
		// PeeringDB: anonymous API, 20 requests/min; its AUP allows research
		// use and forbids passing the data on in bulk, so each user fetches it.
		{
			Name: "peeringdb-ixpfx", File: "peeringdb-ixpfx.json",
			URL: fixed("https://www.peeringdb.com/api/ixpfx"), MinAge: day,
			MaxBytes: 100 * mb, MaxRaw: 100 * mb, MinRows: 500,
			Validate: func(r io.Reader) (int, error) { return ReadIXPrefixes(r, func(IXPrefix) error { return nil }) },
		},
		{
			Name: "peeringdb-netixlan", File: "peeringdb-netixlan.json",
			URL: fixed("https://www.peeringdb.com/api/netixlan"), MinAge: day,
			MaxBytes: 500 * mb, MaxRaw: 500 * mb, MinRows: 10_000,
			Validate: func(r io.Reader) (int, error) { return ReadIXMembers(r, func(IXMember) error { return nil }) },
		},
		// LACeS anycast census (University of Twente), daily. The data terms are
		// not stated; the authors publish it openly and ask to be cited.
		{
			Name: "laces-anycast", File: "anycast-ipv4.csv", MinAge: day,
			URL:      fixed("https://raw.githubusercontent.com/ut-dacs/Anycast-Census/main/IPv4-latest.csv"),
			MaxBytes: 50 * mb, MaxRaw: 50 * mb, MinRows: 5_000,
			Validate: func(r io.Reader) (int, error) { return ReadAnycastCensus(r, func(AnycastPrefix) error { return nil }) },
		},
		{
			Name: "laces-anycast-v6", File: "anycast-ipv6.csv", MinAge: day,
			URL:      fixed("https://raw.githubusercontent.com/ut-dacs/Anycast-Census/main/IPv6-latest.csv"),
			MaxBytes: 50 * mb, MaxRaw: 50 * mb, MinRows: 500,
			Validate: func(r io.Reader) (int, error) { return ReadAnycastCensus(r, func(AnycastPrefix) error { return nil }) },
		},
		{
			Name: "ipinfo", MinAge: day, File: "ipinfo_lite.csv.gz", Gzip: true, NeedsToken: true,
			URL: func(_ time.Time, t Token) string {
				return "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=" + url.QueryEscape(t.reveal())
			},
			MaxBytes: gb, MaxRaw: 4 * gb, MinRows: 1_000_000,
			Validate: func(r io.Reader) (int, error) { return ReadIPinfoLite(r, func(ASNRange) error { return nil }) },
		},
	}
}

func fixed(u string) func(time.Time, Token) string {
	return func(time.Time, Token) string { return u }
}

// monthly names DB-IP files by month; early in a month the new file may not
// exist yet, and the caller keeps the current one.
func monthly(format string) func(time.Time, Token) string {
	return func(now time.Time, _ Token) string {
		return fmt.Sprintf(format, now.UTC().Format("2006-01"))
	}
}
