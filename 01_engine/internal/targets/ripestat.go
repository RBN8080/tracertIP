package targets

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
)

// RIPEstat Data API: public, no key; at most 8 requests at a time per IP and
// registration above 1000 a day. The validator asks one at a time.
var ripestatURL = "https://stat.ripe.net/data/prefix-overview/data.json"

// Routing is what BGP says about the prefix that covers an address.
type Routing struct {
	Prefix    string
	Announced bool
	Origins   []int // more than one: MOAS
}

// PrefixOverview asks RIPEstat which prefix covers a and who originates it.
func PrefixOverview(ctx context.Context, c *http.Client, a netip.Addr, userAgent string) (Routing, error) {
	var body struct {
		Data struct {
			Resource  string `json:"resource"`
			Announced bool   `json:"announced"`
			ASNs      []struct {
				ASN int `json:"asn"`
			} `json:"asns"`
		} `json:"data"`
	}
	u := ripestatURL + "?sourceapp=tracertip&resource=" + url.QueryEscape(a.String())
	if err := getJSON(ctx, c, u, userAgent, &body); err != nil {
		return Routing{}, err
	}
	r := Routing{Prefix: body.Data.Resource, Announced: body.Data.Announced}
	for _, x := range body.Data.ASNs {
		r.Origins = append(r.Origins, x.ASN)
	}
	return r, nil
}
