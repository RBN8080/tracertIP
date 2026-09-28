//go:build !linux

package probe

import "errors"

// Open is Linux-only: Paris probing needs a raw socket that keeps a constant
// ICMP identifier, which is unproven on other systems (00_IDEA 11).
func Open() (Conn, error) {
	return nil, errors.New("probe: raw ICMP probing is supported on Linux only")
}
