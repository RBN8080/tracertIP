//go:build !linux

package probe

import (
	"errors"
	"net"
	"net/netip"
)

// Open is Linux-only: Paris probing needs a raw socket that keeps a constant
// ICMP identifier, which is unproven on other systems (00_IDEA 11).
func Open(netip.Addr) (Conn, error) {
	return nil, errors.New("probe: raw ICMP probing is supported on Linux only")
}

// SourceFor returns the address the system would use to reach dst.
func SourceFor(dst netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}
