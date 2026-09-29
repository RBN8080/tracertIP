package enrich

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// Info is everything known about one address, each answer with its source.
type Info struct {
	Addr    string   `json:"addr"`
	Class   string   `json:"class"`
	RFC     string   `json:"rfc,omitempty"`
	AS      []AS     `json:"as,omitempty"`     // all bases that answered; never invented
	Name    string   `json:"name,omitempty"`   // PTR
	Places  []Place  `json:"places,omitempty"` // from the name: inference
	DBCity  *City    `json:"db_city,omitempty"`
	IXP     *IXP     `json:"ixp,omitempty"`
	Anycast *Anycast `json:"anycast,omitempty"` // listed by a census
	IPmap   *IPmap   `json:"ipmap,omitempty"`   // RIPE IPmap: city, measured or named
}

// Options says where the bases are and how to resolve names.
type Options struct {
	Dir      string // bases folder (update-db)
	Hints    string // optional hint table; default Dir/geohints.tsv
	Resolver string // "host:port"; empty = system resolver
	NoDNS    bool
	NoCity   bool // skip the city base; see DBCity
	// RIPE IPmap. Home-side addresses (the access ISP's AS) are never sent.
	NoIPmap    bool
	IPmapCache string // file; empty = no cache
	AccessASN  int
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
	db, err := lookupBases(o.Dir, public, true, !o.NoCity)
	if err != nil {
		return nil, err
	}
	ixps, err := lookupIXPs(o.Dir, public)
	if err != nil {
		return nil, err
	}
	census, err := lookupAnycast(o.Dir, public)
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
	var located map[netip.Addr]*IPmap
	if !o.NoIPmap {
		var ask []netip.Addr
		for _, a := range public {
			if d := db[a]; o.AccessASN == 0 || d == nil || len(d.asn) == 0 || d.asn[0].ASN != o.AccessASN {
				ask = append(ask, a)
			}
		}
		located = lookupIPmap(ctx, o.IPmapCache, ask, time.Now())
	}
	for _, a := range public {
		inf := out[a]
		inf.IPmap = located[a]
		if d := db[a]; d != nil {
			inf.AS, inf.DBCity = d.asn, d.city
		}
		inf.IXP = ixps[a]
		inf.Anycast = census[a]
		inf.Name = names[a]
		if hints != nil && inf.Name != "" {
			inf.Places = hints.For(inf.Name)
		}
		out[a] = inf
	}
	return out, nil
}

// DBCity looks a single address up in the city base alone, so that a trace can
// run it while it probes.
func DBCity(dir string, a netip.Addr) (*City, error) {
	if class, _ := Classify(a); class != ClassPublic {
		return nil, nil
	}
	db, err := lookupBases(dir, []netip.Addr{a}, false, true)
	if err != nil {
		return nil, err
	}
	return db[a].city, nil
}
