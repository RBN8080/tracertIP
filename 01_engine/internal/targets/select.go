package targets

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
)

// Roles in a target list.
const (
	RoleStudy   = "study"
	RoleReserve = "reserve" // replaces a study target of its continent, in order
	RoleFixed   = "fixed"   // chosen by hand, not an anchor (Panama, T2)
)

// Check is one test a target passed or failed.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Target is a checked candidate.
type Target struct {
	Anchor
	Continent string  `json:"continent,omitempty"`
	Role      string  `json:"role,omitempty"`
	Rank      int     `json:"rank,omitempty"` // order within its continent and role
	Checks    []Check `json:"checks,omitempty"`
}

// Passed says whether every check passed.
func (t *Target) Passed() bool {
	return !slices.ContainsFunc(t.Checks, func(c Check) bool { return !c.OK })
}

// Add records a check.
func (t *Target) Add(name string, ok bool, format string, args ...any) {
	t.Checks = append(t.Checks, Check{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
}

// Options are the selection rules.
type Options struct {
	Continents   []string // AF, AS, EU, NA, OC, SA
	PerContinent int      // study targets per continent
	Reserve      int      // reserve targets per continent
	Seed         string   // makes the order reproducible
}

// Eligible keeps active dual-stack anchors with a declared location, a
// known continent and neither address in exclude. The reason says why not.
func Eligible(a Anchor, continent string, public func(netip.Addr) bool, exclude map[netip.Addr]bool) (bool, string) {
	switch {
	case !a.Active:
		return false, "not active"
	case !a.IPv4.Is4() || !a.IPv6.Is6() || a.ASv4 == 0 || a.ASv6 == 0:
		return false, "not dual-stack"
	case !public(a.IPv4) || !public(a.IPv6):
		return false, "not a public address"
	case a.Lat == 0 && a.Lon == 0:
		return false, "no declared location"
	case continent == "":
		return false, "unknown continent"
	case exclude[a.IPv4] || exclude[a.IPv6]:
		return false, "excluded (already measured)"
	}
	return true, ""
}

// Select picks, per continent, PerContinent study targets and Reserve more.
// Candidates are taken in a seeded order, one country at a time in turn, so
// countries are spread as evenly as the anchors allow, and never two from
// one AS. verify runs the costly checks and reports whether all passed;
// rejected targets are returned with their checks.
func Select(cands []Target, o Options, verify func(*Target) bool) (chosen, rejected []Target) {
	for _, cont := range o.Continents {
		byCountry := map[string][]Target{}
		var countries []string
		for _, t := range cands {
			if t.Continent != cont {
				continue
			}
			if _, ok := byCountry[t.Country]; !ok {
				countries = append(countries, t.Country)
			}
			byCountry[t.Country] = append(byCountry[t.Country], t)
		}
		for _, c := range countries {
			slices.SortFunc(byCountry[c], func(a, b Target) int { return cmpKey(o.Seed, a.ID, b.ID) })
		}
		slices.SortFunc(countries, func(a, b string) int { return cmpKey(o.Seed, keyOf(a), keyOf(b)) })

		usedAS := map[int]bool{}
		picked := 0
		want := o.PerContinent + o.Reserve
		for picked < want {
			progress := false
			for _, c := range countries {
				if picked == want {
					break
				}
				q := byCountry[c]
				for len(q) > 0 {
					t := q[0]
					q = q[1:]
					if usedAS[t.ASv4] || usedAS[t.ASv6] {
						continue // another anchor of this network is in
					}
					if !verify(&t) {
						rejected = append(rejected, t)
						continue
					}
					usedAS[t.ASv4], usedAS[t.ASv6] = true, true
					picked++
					t.Role, t.Rank = RoleStudy, picked
					if picked > o.PerContinent {
						t.Role, t.Rank = RoleReserve, picked-o.PerContinent
					}
					chosen = append(chosen, t)
					progress = true
					break
				}
				byCountry[c] = q
			}
			if !progress {
				break // the continent ran out of candidates
			}
		}
	}
	return chosen, rejected
}

// cmpKey orders ids by a hash of the seed: random-looking, but repeatable.
func cmpKey(seed string, a, b int) int {
	ka, kb := hashKey(seed, a), hashKey(seed, b)
	switch {
	case ka < kb:
		return -1
	case ka > kb:
		return 1
	}
	return a - b
}

func hashKey(seed string, id int) uint64 {
	h := sha256.Sum256(fmt.Appendf(nil, "%s:%d", seed, id))
	return binary.BigEndian.Uint64(h[:8])
}

// keyOf turns a country code into an id for the seeded order.
func keyOf(country string) int {
	k := 0
	for _, r := range country {
		k = k*256 + int(r)
	}
	return k
}
