package enrich

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

// IXP labels an address on an exchange's peering LAN. MemberASN is the
// network that holds the address, if PeeringDB lists it; 0 = member unknown.
// The exchange's own AS is never used (bdrmap, IMC 2016).
type IXP struct {
	Name      string `json:"name"`
	MemberASN int    `json:"member_asn,omitempty"`
	Source    string `json:"source"`
}

// lookupIXPs answers from the PeeringDB files; absent files answer nothing.
func lookupIXPs(dir string, addrs []netip.Addr) (map[netip.Addr]*IXP, error) {
	out := map[netip.Addr]*IXP{}
	var prefixes []ipdb.IXPrefix
	err := readFile(filepath.Join(dir, "peeringdb-ixpfx.json"), func(f *os.File) error {
		_, err := ipdb.ReadIXPrefixes(f, func(p ipdb.IXPrefix) error { prefixes = append(prefixes, p); return nil })
		return err
	})
	if errors.Is(err, os.ErrNotExist) || len(prefixes) == 0 {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	members := map[netip.Addr]int{}
	err = readFile(filepath.Join(dir, "peeringdb-netixlan.json"), func(f *os.File) error {
		_, err := ipdb.ReadIXMembers(f, func(m ipdb.IXMember) error {
			names[m.IXLanID] = m.IXName
			if m.Addr.IsValid() {
				members[m.Addr] = m.ASN
			}
			return nil
		})
		return err
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, a := range addrs {
		for _, p := range prefixes {
			if p.Prefix.Contains(a) {
				name := names[p.IXLanID]
				if name == "" {
					name = "unnamed IXP"
				}
				out[a] = &IXP{Name: name, MemberASN: members[a], Source: "peeringdb"}
				break
			}
		}
	}
	return out, nil
}

func readFile(path string, fn func(*os.File) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}
