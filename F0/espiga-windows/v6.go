//go:build windows

package main

// IPv6 (paso 0.1, intento acotado a 30 min): Icmp6SendEcho2 en modo sincrono
// (sin evento ni APC), con el mismo TTL creciente que en IPv4.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

func trazar6(ip net.IP) {
	h, _, err := iphlpapi.NewProc("Icmp6CreateFile").Call()
	if syscall.Handle(h) == syscall.InvalidHandle {
		fmt.Fprintln(os.Stderr, "Icmp6CreateFile:", err)
		os.Exit(1)
	}
	defer iphlpapi.NewProc("IcmpCloseHandle").Call(h)
	enviar := iphlpapi.NewProc("Icmp6SendEcho2")
	src := syscall.RawSockaddrInet6{Family: syscall.AF_INET6} // origen: cualquiera
	dst := syscall.RawSockaddrInet6{Family: syscall.AF_INET6}
	copy(dst.Addr[:], ip.To16())
	datos, buf := make([]byte, 32), make([]byte, 256)
	for ttl := 1; ttl <= ttlMaximo; ttl++ {
		opt := ipOptionInformation{Ttl: uint8(ttl)}
		clear(buf)
		n, _, e := enviar.Call(h, 0, 0, 0, uintptr(unsafe.Pointer(&src)), uintptr(unsafe.Pointer(&dst)),
			uintptr(unsafe.Pointer(&datos[0])), uintptr(len(datos)), uintptr(unsafe.Pointer(&opt)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), plazoMs)
		if n == 0 {
			fmt.Printf("%d\t*\t-\t-\t0\t%d\n", ttl, e.(syscall.Errno))
			continue
		}
		// ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX empaquetada (puerto 2, flowinfo 4,
		// direccion 16 y scope 4 = 26 bytes); luego Status en el desplazamiento
		// 28 (ULONG alineado a 4) y RoundTripTime en el 32.
		de := net.IP(buf[6:22])
		st, rtt := binary.LittleEndian.Uint32(buf[28:32]), binary.LittleEndian.Uint32(buf[32:36])
		fmt.Printf("%d\t%s\t%s\t%d\t%d\t%d\n", ttl, de, estado(st), rtt, n, e.(syscall.Errno))
		if st == 0 {
			return
		}
	}
}
