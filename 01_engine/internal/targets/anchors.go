// Package targets chooses measurement targets: RIPE Atlas anchors, built
// to be measured and with a location their hosts declare (RIPE NCC, IPJ
// 2015), that pass every check, spread over the continents, with a reserve.
package targets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
)

// Anchor is one RIPE Atlas anchor.
type Anchor struct {
	ID      int        `json:"id"`
	FQDN    string     `json:"fqdn,omitempty"`
	IPv4    netip.Addr `json:"ip_v4,omitzero"`
	IPv6    netip.Addr `json:"ip_v6,omitzero"`
	ASv4    int        `json:"as_v4,omitempty"`
	ASv6    int        `json:"as_v6,omitempty"`
	City    string     `json:"city,omitempty"`
	Country string     `json:"country,omitempty"`
	Lat     float64    `json:"lat,omitempty"`
	Lon     float64    `json:"lon,omitempty"`
	Active  bool       `json:"-"` // not disabled nor decommissioned
}

type rawAnchor struct {
	ID       int     `json:"id"`
	FQDN     string  `json:"fqdn"`
	IPv4     *string `json:"ip_v4"`
	IPv6     *string `json:"ip_v6"`
	ASv4     *int    `json:"as_v4"`
	ASv6     *int    `json:"as_v6"`
	City     string  `json:"city"`
	Country  string  `json:"country"`
	Disabled bool    `json:"is_disabled"`
	Retired  *string `json:"date_decommissioned"`
	Geometry *struct {
		Coordinates []float64 `json:"coordinates"` // GeoJSON: longitude, latitude
	} `json:"geometry"`
}

func (r rawAnchor) anchor() Anchor {
	a := Anchor{ID: r.ID, FQDN: r.FQDN, City: r.City, Country: strings.ToUpper(r.Country),
		Active: !r.Disabled && r.Retired == nil}
	if r.IPv4 != nil {
		a.IPv4, _ = netip.ParseAddr(*r.IPv4)
	}
	if r.IPv6 != nil {
		a.IPv6, _ = netip.ParseAddr(*r.IPv6)
	}
	if r.ASv4 != nil {
		a.ASv4 = *r.ASv4
	}
	if r.ASv6 != nil {
		a.ASv6 = *r.ASv6
	}
	if g := r.Geometry; g != nil && len(g.Coordinates) == 2 {
		a.Lon, a.Lat = g.Coordinates[0], g.Coordinates[1]
	}
	return a
}

// ReadAnchors reads a saved list: a JSON array of API results.
func ReadAnchors(r io.Reader) ([]Anchor, error) {
	var raw []rawAnchor
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]Anchor, len(raw))
	for i, x := range raw {
		out[i] = x.anchor()
	}
	return out, nil
}

// AnchorsURL is the public list; no account is needed to read it.
var AnchorsURL = "https://atlas.ripe.net/api/v2/anchors/?format=json&page_size=500"

// FetchAnchors follows the API's pages and returns the anchors and the raw
// results as one JSON array, to be kept with the data (Paxson, IMC 2004).
func FetchAnchors(ctx context.Context, c *http.Client, userAgent string) ([]Anchor, []byte, error) {
	var all []json.RawMessage
	next := AnchorsURL
	for page := 0; next != ""; page++ {
		if page > 100 {
			return nil, nil, errors.New("anchors: too many pages")
		}
		var body struct {
			Next    *string           `json:"next"`
			Results []json.RawMessage `json:"results"`
		}
		if err := getJSON(ctx, c, next, userAgent, &body); err != nil {
			return nil, nil, fmt.Errorf("anchors: %w", err)
		}
		all = append(all, body.Results...)
		next = ""
		if body.Next != nil {
			next = *body.Next
		}
	}
	raw, err := json.Marshal(all)
	if err != nil {
		return nil, nil, err
	}
	a, err := ReadAnchors(strings.NewReader(string(raw)))
	return a, raw, err
}

const maxBody = 64 << 20

func getJSON(ctx context.Context, c *http.Client, url, userAgent string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v)
}
