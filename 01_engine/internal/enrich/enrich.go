package enrich

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
)

// Info is everything known about one address, each answer with its source.
type Info struct {
	Addr   string  `json:"addr"`
	Class  string  `json:"class"`
	RFC    string  `json:"rfc,omitempty"`
	AS     []AS    `json:"as,omitempty"`     // all bases that answered; never invented
	Name   string  `json:"name,omitempty"`   // PTR
	Places []Place `json:"places,omitempty"` // from the name: inference
	DBCity *City   `json:"db_city,omitempty"`
	IXP    *IXP    `json:"ixp,omitempty"`
}

// Options says where the bases are and how to resolve names.
type Options struct {
	Dir      string // bases folder (update-db)
	Hints    string // optional hint table; default Dir/geohints.tsv
	Resolver string // "host:port"; empty = system resolver
	NoDNS    bool
}

// Enrich answers for every address. Special-purpose addresses get their class
// and no AS; missing bases simply answer nothing.
func Enrich(ctx context.Context, addrs []netip.Addr, o Options) (map[netip.Addr]Info, error) {
	var public []netip.Addr
	out := map[netip.Addr]Info{}
	for _, a := range addrs {
		class, rfc := Classify(a)
		out[a] = Info{Addr: a.String(), Class: class, RFC: rfc}
		if class == ClassPublic {
			public = append(public, a)
		}
	}
	db, err := lookupBases(o.Dir, public)
	if err != nil {
		return nil, err
	}
	ixps, err := lookupIXPs(o.Dir, public)
	if err != nil {
		return nil, err
	}
	var names map[netip.Addr]string
	if !o.NoDNS {
		names = lookupNames(ctx, newResolver(o.Resolver), public)
	}
	table := o.Hints
	if table == "" {
		table = filepath.Join(o.Dir, "geohints.tsv")
	}
	hints, err := LoadHints(filepath.Join(o.Dir, "airports.csv"), table)
	if errors.Is(err, os.ErrNotExist) {
		hints = nil // no airports base: no name hints (empty Places)
	} else if err != nil {
		return nil, err // a bad hint table fails loudly (P5)
	}
	for _, a := range public {
		inf := out[a]
		if d := db[a]; d != nil {
			inf.AS, inf.DBCity = d.asn, d.city
		}
		inf.IXP = ixps[a]
		inf.Name = names[a]
		if hints != nil && inf.Name != "" {
			inf.Places = hints.For(inf.Name)
		}
		out[a] = inf
	}
	return out, nil
}
