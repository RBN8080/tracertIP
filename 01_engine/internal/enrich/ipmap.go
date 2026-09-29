package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

// IPmap is RIPE IPmap's best city for an infrastructure address. Its latency
// engine places the address near a RIPE Atlas probe of known location that
// reached it within MinRTT ms (Du et al., CCR 2020: 80% right at city level,
// better than commercial bases for routers).
type IPmap struct {
	City     string   `json:"city"`
	Country  string   `json:"country"`
	Lat      float64  `json:"lat"`
	Lon      float64  `json:"lon"`
	Engines  []string `json:"engines"`              // e.g. latency, ixp, reverse-dns
	MinRTT   float64  `json:"min_rtt_ms,omitempty"` // latency engine: nearest probe
	RadiusKm float64  `json:"radius_km,omitempty"`
}

// nearMs: a probe within 1 ms round trip is within about 100 km, the scale of
// a city. Farther probes only bound a wide disk, and IPmap then picks the
// city in it by population.
const nearMs = 1.0

// Measured says whether a nearby probe's latency places the city.
func (m *IPmap) Measured() bool {
	return slices.Contains(m.Engines, "latency") && m.MinRTT > 0 && m.MinRTT <= nearMs
}

// Backed says whether the router's name or an IXP supports the city.
func (m *IPmap) Backed() bool {
	return slices.ContainsFunc(m.Engines, func(e string) bool { return e == "reverse-dns" || e == "ixp" })
}

// IPmap service: public, no key; RIPE NCC terms for public services apply.
var ipmapURL = "https://ipmap-api.ripe.net/v1/locate/all"

const (
	ipmapBatch   = 50
	ipmapTimeout = 15 * time.Second
	ipmapMaxBody = 8 << 20
	ipmapTTL     = 7 * 24 * time.Hour // its latency data is refreshed daily
)

type ipmapEntry struct {
	Time time.Time `json:"time"`
	Loc  *IPmap    `json:"loc"` // nil: IPmap had no answer
}

// lookupIPmap asks IPmap about addrs not answered in the cache. Failures
// leave addresses without an answer: IPmap is one source among several.
func lookupIPmap(ctx context.Context, cache string, addrs []netip.Addr, now time.Time) map[netip.Addr]*IPmap {
	known := readIPmapCache(cache)
	out := map[netip.Addr]*IPmap{}
	var ask []netip.Addr
	for _, a := range addrs {
		if e, ok := known[a.String()]; ok && now.Sub(e.Time) < ipmapTTL {
			out[a] = e.Loc
		} else {
			ask = append(ask, a)
		}
	}
	if len(ask) == 0 {
		return out
	}
	c := ipdb.NewClient(ipmapTimeout)
	asked := false
	for chunk := range slices.Chunk(ask, ipmapBatch) {
		got, err := queryIPmap(ctx, c, chunk)
		if err != nil {
			continue
		}
		asked = true
		for _, a := range chunk {
			out[a] = got[a]
			known[a.String()] = ipmapEntry{Time: now.UTC(), Loc: got[a]}
		}
	}
	if asked && cache != "" {
		writeIPmapCache(cache, known) // best effort: a lost cache only costs a query
	}
	return out
}

func queryIPmap(ctx context.Context, c *http.Client, addrs []netip.Addr) (map[netip.Addr]*IPmap, error) {
	var list []string
	for _, a := range addrs {
		list = append(list, a.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipmapURL+"?resources="+url.QueryEscape(strings.Join(list, ",")), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ipdb.UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipmap: HTTP %d", resp.StatusCode)
	}
	return parseIPmap(io.LimitReader(resp.Body, ipmapMaxBody))
}

// parseIPmap reads a /locate/all answer. The "worlds" engine only weighs city
// population, so a city backed by nothing else is dropped.
func parseIPmap(r io.Reader) (map[netip.Addr]*IPmap, error) {
	var body struct {
		Data map[string]*struct {
			Type          string                     `json:"type"`
			City          string                     `json:"cityNameAscii"`
			Country       string                     `json:"countryCodeAlpha2"`
			Lat           *float64                   `json:"latitude"`
			Lon           *float64                   `json:"longitude"`
			Contributions map[string]json.RawMessage `json:"contributions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		return nil, err
	}
	if body.Data == nil {
		return nil, errors.New("ipmap: no data")
	}
	out := map[netip.Addr]*IPmap{}
	for k, d := range body.Data {
		a, err := netip.ParseAddr(k)
		if err != nil || d == nil || d.Type != "city" || d.Lat == nil || d.Lon == nil {
			continue
		}
		m := &IPmap{City: d.City, Country: d.Country, Lat: *d.Lat, Lon: *d.Lon}
		for e, raw := range d.Contributions {
			if e == "worlds" {
				continue
			}
			m.Engines = append(m.Engines, e)
			if e == "latency" {
				var l struct {
					MinRTT float64 `json:"minRtt"`
					Radius struct {
						Metres float64 `json:"maxDistanceMetres"`
					} `json:"radius"`
				}
				if json.Unmarshal(raw, &l) == nil {
					m.MinRTT, m.RadiusKm = l.MinRTT, l.Radius.Metres/1000
				}
			}
		}
		if len(m.Engines) == 0 {
			continue
		}
		slices.Sort(m.Engines)
		out[a.Unmap()] = m
	}
	return out, nil
}

func readIPmapCache(path string) map[string]ipmapEntry {
	m := map[string]ipmapEntry{}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &m) // a damaged cache is just empty
	}
	return m
}

func writeIPmapCache(path string, m map[string]ipmapEntry) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return ipdb.WriteAtomic(path, b, 0o600)
}
