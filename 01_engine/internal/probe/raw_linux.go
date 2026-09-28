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

// Linux raw socket options (include/uapi/linux/icmp.h; raw(7), icmp(7)).
const (
	solRaw     = 255 // SOL_RAW
	icmpFilter = 1   // ICMP_FILTER: bit n set drops ICMP type n
)

type rawConn struct{ c *net.IPConn }

// Open opens a raw ICMP socket; it needs CAP_NET_RAW (capabilities(7)).
func Open() (Conn, error) {
	pc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("%w: raw ICMP needs CAP_NET_RAW (setcap cap_net_raw+ep on the binary, or a service with AmbientCapabilities=CAP_NET_RAW)", err)
		}
		return nil, err
	}
	c := pc.(*net.IPConn)
	keep := uint32(1<<icmpEchoReply | 1<<icmpUnreachable | 1<<icmpTimeExceed)
	if err := control(c, func(fd int) error {
		return syscall.SetsockoptInt(fd, solRaw, icmpFilter, int(^keep))
	}); err != nil {
		c.Close()
		return nil, fmt.Errorf("ICMP_FILTER: %w", err)
	}
	return &rawConn{c}, nil
}

func (r *rawConn) Send(dst netip.Addr, ttl int, icmp []byte) error {
	if err := control(r.c, func(fd int) error {
		return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	}); err != nil {
		return fmt.Errorf("IP_TTL: %w", err)
	}
	_, err := r.c.WriteToIP(icmp, &net.IPAddr{IP: dst.AsSlice()})
	return err
}

// Recv returns a whole IPv4 packet: ReadMsgIP keeps the header, ReadFrom strips it.
func (r *rawConn) Recv(buf []byte, deadline time.Time) (int, error) {
	if err := r.c.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	n, _, _, _, err := r.c.ReadMsgIP(buf, nil)
	return n, err
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
