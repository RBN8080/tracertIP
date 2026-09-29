//go:build linux

package probe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Linux raw socket options (include/uapi/linux/icmp.h, icmpv6.h, in6.h;
// raw(7), icmp(7), ipv6(7); RFC 3542).
const (
	solRaw            = 255 // SOL_RAW
	icmpFilter        = 1   // ICMP_FILTER: bit n set drops ICMP type n
	icmp6Filter       = 1   // ICMP6_FILTER at IPPROTO_ICMPV6: bit n set blocks type n
	ipv6UnicastHops   = 16  // IPV6_UNICAST_HOPS
	ipv6RecvHopLimit  = 51  // IPV6_RECVHOPLIMIT
	ipv6HopLimitCmsg  = 52  // IPV6_HOPLIMIT control message
	ipprotoICMPv6     = 58
	hopLimitCmsgBytes = 64
)

type rawConn struct {
	c  *net.IPConn
	v6 bool
}

// Open opens a raw ICMP (IPv4) or ICMPv6 socket for target's family; it needs
// CAP_NET_RAW (capabilities(7)).
func Open(target netip.Addr) (Conn, error) {
	v6 := target.Is6() && !target.Is4In6()
	network, laddr := "ip4:icmp", "0.0.0.0"
	if v6 {
		network, laddr = "ip6:ipv6-icmp", "::"
	}
	pc, err := net.ListenPacket(network, laddr)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("%w: raw ICMP needs CAP_NET_RAW (setcap cap_net_raw+ep on the binary, or a service with AmbientCapabilities=CAP_NET_RAW)", err)
		}
		return nil, err
	}
	c := pc.(*net.IPConn)
	if err := control(c, func(fd int) error {
		if !v6 {
			keep := uint32(1<<icmpEchoReply | 1<<icmpUnreachable | 1<<icmpTimeExceed)
			return syscall.SetsockoptInt(fd, solRaw, icmpFilter, int(^keep))
		}
		var f [32]byte // 256 bits, one per ICMPv6 type; set = blocked
		for i := range f {
			f[i] = 0xff
		}
		for _, t := range []int{icmp6Unreachable, icmp6TimeExceed, icmp6EchoReply} {
			f[t/8] &^= 1 << (t % 8)
		}
		if err := syscall.SetsockoptString(fd, ipprotoICMPv6, icmp6Filter, string(f[:])); err != nil {
			return err
		}
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, ipv6RecvHopLimit, 1)
	}); err != nil {
		c.Close()
		return nil, fmt.Errorf("socket options: %w", err)
	}
	return &rawConn{c: c, v6: v6}, nil
}

// SourceFor returns the address the kernel would use to reach dst. Connecting
// a UDP socket only picks the route; no packet is sent.
func SourceFor(dst netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

func (r *rawConn) Send(dst netip.Addr, ttl int, icmp []byte) error {
	if err := control(r.c, func(fd int) error {
		if r.v6 {
			return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, ipv6UnicastHops, ttl)
		}
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}); err != nil {
		return fmt.Errorf("TTL: %w", err)
	}
	_, err := r.c.WriteToIP(icmp, &net.IPAddr{IP: dst.AsSlice()})
	return err
}

// Recv: for IPv4, the whole packet (ReadMsgIP keeps the header, ReadFrom
// strips it); for IPv6, the ICMPv6 message, with sender and hop limit in Meta.
func (r *rawConn) Recv(buf []byte, deadline time.Time) (int, Meta, error) {
	if err := r.c.SetReadDeadline(deadline); err != nil {
		return 0, Meta{}, err
	}
	var oob []byte
	if r.v6 {
		oob = make([]byte, hopLimitCmsgBytes)
	}
	n, oobn, _, from, err := r.c.ReadMsgIP(buf, oob)
	if err != nil || !r.v6 {
		return n, Meta{}, err
	}
	m := Meta{HopLimit: -1}
	if a, ok := netip.AddrFromSlice(from.IP); ok {
		m.From = a.Unmap()
	}
	if msgs, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, c := range msgs {
			if c.Header.Level == syscall.IPPROTO_IPV6 && c.Header.Type == ipv6HopLimitCmsg && len(c.Data) >= 4 {
				m.HopLimit = int(int32(uint32(c.Data[0]) | uint32(c.Data[1])<<8 | uint32(c.Data[2])<<16 | uint32(c.Data[3])<<24))
			}
		}
	}
	return n, m, nil
}

func (r *rawConn) Close() error { return r.c.Close() }

func control(c *net.IPConn, f func(fd int) error) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}
