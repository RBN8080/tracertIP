package ipdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// IXPrefix is an IXP peering LAN (PeeringDB ixpfx).
type IXPrefix struct {
	Prefix  netip.Prefix
	IXLanID int
}

// IXMember is one network's address on an IXP LAN (PeeringDB netixlan).
type IXMember struct {
	IXLanID int
	IXName  string
	ASN     int
	Addr    netip.Addr // invalid when the member has no IPv4 address
}

// ReadIXPrefixes reads PeeringDB /api/ixpfx, keeping IPv4 prefixes.
func ReadIXPrefixes(r io.Reader, fn func(IXPrefix) error) (int, error) {
	var row struct {
		Protocol string `json:"protocol"`
		Prefix   string `json:"prefix"`
		IXLanID  int    `json:"ixlan_id"`
	}
	return readData(r, &row, func() (bool, error) {
		if row.Protocol != "IPv4" {
			return false, nil
		}
		p, err := netip.ParsePrefix(row.Prefix)
		if err != nil || !p.Addr().Is4() {
			return false, fmt.Errorf("bad prefix %q", row.Prefix)
		}
		return true, fn(IXPrefix{Prefix: p.Masked(), IXLanID: row.IXLanID})
	})
}

// ReadIXMembers reads PeeringDB /api/netixlan.
func ReadIXMembers(r io.Reader, fn func(IXMember) error) (int, error) {
	var row struct {
		IXLanID int     `json:"ixlan_id"`
		Name    string  `json:"name"`
		ASN     int     `json:"asn"`
		IPv4    *string `json:"ipaddr4"`
	}
	return readData(r, &row, func() (bool, error) {
		m := IXMember{IXLanID: row.IXLanID, IXName: row.Name, ASN: row.ASN}
		if row.IPv4 != nil && *row.IPv4 != "" {
			a, err := netip.ParseAddr(*row.IPv4)
			if err != nil {
				return false, fmt.Errorf("bad ipaddr4 %q", *row.IPv4)
			}
			m.Addr = a
		}
		row.IPv4 = nil
		return true, fn(m)
	})
}

// readData streams the "data" array of a PeeringDB response into row, one
// element at a time, so a large response is never held whole in memory.
func readData(r io.Reader, row any, each func() (bool, error)) (int, error) {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return 0, errors.New("not a JSON object")
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return 0, err
		}
		if k != "data" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, err
			}
			continue
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('[') {
			return 0, errors.New(`"data" is not an array`)
		}
		n := 0
		for dec.More() {
			if err := dec.Decode(row); err != nil {
				return n, err
			}
			kept, err := each()
			if err != nil {
				return n, err
			}
			if kept {
				n++
			}
		}
		return n, nil
	}
	return 0, errors.New(`no "data" array`)
}
