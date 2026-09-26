//go:build windows

// tracertIP - F0 - paso 0.1 - espiga: traza con IcmpSendEcho y TTL creciente,
// sin permisos de administrador. Solo decide si el PC puede ser sonda
// secundaria. Uso: espiga <IPv4 | IPv6>
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	ttlMaximo = 40   // TTL_MAXIMO de la frontera (calibrado en 0.2)
	plazoMs   = 2000 // TIMEOUT_SONDA de la frontera
)

var iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

type ipOptionInformation struct {
	Ttl, Tos, Flags, OptionsSize uint8
	OptionsData                  uintptr // desplazamiento 8; tamano total 16
}

type icmpEchoReply struct {
	Address       uint32 // IPAddr, en orden de red
	Status        uint32
	RoundTripTime uint32 // ms
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation // tamano total 40
}

// estado traduce los codigos IP_* de ipexport.h que importan aqui.
func estado(s uint32) string {
	switch s {
	case 0:
		return "destino" // IP_SUCCESS
	case 11013:
		return "ttl_expirado" // IP_TTL_EXPIRED_TRANSIT
	case 11010:
		return "plazo_vencido" // IP_REQ_TIMED_OUT
	case 11003:
		return "inalcanzable" // IP_DEST_HOST_UNREACHABLE
	}
	return fmt.Sprint(s)
}

func main() {
	var ip net.IP
	if len(os.Args) == 2 {
		ip = net.ParseIP(os.Args[1])
	}
	if ip == nil {
		fmt.Fprintln(os.Stderr, "uso: espiga <IPv4 | IPv6>")
		os.Exit(2)
	}
	fmt.Println("ttl\tip\testado\trtt_ms\trespuestas\tGetLastError")
	if ip.To4() == nil {
		trazar6(ip)
		return
	}
	v4 := ip.To4()
	h, _, err := iphlpapi.NewProc("IcmpCreateFile").Call()
	if syscall.Handle(h) == syscall.InvalidHandle {
		fmt.Fprintln(os.Stderr, "IcmpCreateFile:", err)
		os.Exit(1)
	}
	defer iphlpapi.NewProc("IcmpCloseHandle").Call(h)
	enviar := iphlpapi.NewProc("IcmpSendEcho")
	dst := uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
	datos, buf := make([]byte, 32), make([]byte, 256) // buf >= 40 + 32 + 8
	for ttl := 1; ttl <= ttlMaximo; ttl++ {
		opt := ipOptionInformation{Ttl: uint8(ttl)}
		clear(buf)
		n, _, e := enviar.Call(h, uintptr(dst), uintptr(unsafe.Pointer(&datos[0])), uintptr(len(datos)),
			uintptr(unsafe.Pointer(&opt)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), plazoMs)
		r := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
		if n == 0 {
			fmt.Printf("%d\t*\t-\t-\t0\t%d\n", ttl, e.(syscall.Errno))
			continue
		}
		de := net.IPv4(byte(r.Address), byte(r.Address>>8), byte(r.Address>>16), byte(r.Address>>24))
		fmt.Printf("%d\t%s\t%s\t%d\t%d\t%d\n", ttl, de, estado(r.Status), r.RoundTripTime, n, e.(syscall.Errno))
		if r.Status == 0 {
			return
		}
	}
}
