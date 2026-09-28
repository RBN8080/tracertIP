package main

// Clase de cada direccion y ASN por salto. El ASN sale de IPinfo Lite y, si
// falta, de DB-IP Lite (instruccion 12.1); si faltan los dos, es AS?.

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const mudo = "???" // mtr: salto que no contesto ninguna sonda

var (
	redesPrivadas = []netip.Prefix{ // RFC 1918
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	redCGNAT       = netip.MustParsePrefix("100.64.0.0/10")  // RFC 6598
	redEnlaceLocal = netip.MustParsePrefix("169.254.0.0/16") // RFC 3927
)

type clase int

const (
	claseMudo clase = iota
	clasePrivada
	claseCGNAT
	claseEnlaceLocal
	clasePublica
	claseInvalida
)

// clasificar dice que es un host de mtr. Solo IPv4: la F0 mide IPv4.
func clasificar(host string) clase {
	if host == mudo {
		return claseMudo
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.Is4() {
		return claseInvalida
	}
	for _, p := range redesPrivadas {
		if p.Contains(a) {
			return clasePrivada
		}
	}
	switch {
	case redCGNAT.Contains(a):
		return claseCGNAT
	case redEnlaceLocal.Contains(a):
		return claseEnlaceLocal
	}
	return clasePublica
}

// infoASN: el ASN de una direccion y de donde salio. ASN 0 = desconocido.
type infoASN struct {
	ASN    int
	Nombre string
	Fuente string // "IPinfo" o "DB-IP"
}

type tablaASN map[netip.Addr]infoASN

func (t tablaASN) de(host string) infoASN {
	a, err := netip.ParseAddr(host)
	if err != nil {
		return infoASN{}
	}
	return t[a]
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func addr(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// resolverASN busca el ASN de cada direccion IPv4: primero en IPinfo Lite y,
// si falta, en DB-IP Lite. Recorre cada base una vez sin cargarla en memoria:
// por cada rango, busqueda binaria entre las direcciones buscadas.
func resolverASN(buscadas []netip.Addr, rutaIPinfo, rutaDBIP string) (tablaASN, error) {
	var claves []uint32
	for _, a := range buscadas {
		if a.Is4() {
			claves = append(claves, u32(a))
		}
	}
	slices.Sort(claves)
	t := tablaASN{}
	asignar := func(lo, hi uint32, info infoASN) {
		i := sort.Search(len(claves), func(i int) bool { return claves[i] >= lo })
		for ; i < len(claves) && claves[i] <= hi; i++ {
			if _, ya := t[addr(claves[i])]; !ya {
				t[addr(claves[i])] = info
			}
		}
	}
	if err := recorrerIPinfo(rutaIPinfo, asignar); err != nil {
		return nil, err
	}
	if err := recorrerDBIP(rutaDBIP, asignar); err != nil {
		return nil, err
	}
	return t, nil
}

// IPinfo Lite: CSV con encabezado (leido del archivo real el 2026-09-26):
// network,country,country_code,continent,continent_code,asn,as_name,as_domain.
// network es un prefijo o una IP suelta (126 719 filas IPv4 del archivo real);
// el ASN viene como "AS13335", o vacio si la red no tiene.
func recorrerIPinfo(ruta string, asignar func(lo, hi uint32, info infoASN)) error {
	return recorrerCSVgz(ruta, func(r *csv.Reader) error {
		enc, err := r.Read()
		if err != nil {
			return err
		}
		col := map[string]int{}
		for i, c := range enc {
			col[c] = i
		}
		iRed, ok1 := col["network"]
		iASN, ok2 := col["asn"]
		iNom, ok3 := col["as_name"]
		if !ok1 || !ok2 || !ok3 {
			return fmt.Errorf("encabezado inesperado: %v", enc)
		}
		r.FieldsPerRecord = len(enc)
		for {
			rec, err := r.Read()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if strings.Contains(rec[iRed], ":") || rec[iASN] == "" { // IPv6 o sin ASN
				continue
			}
			p, err := netip.ParsePrefix(rec[iRed])
			if !strings.Contains(rec[iRed], "/") {
				var a netip.Addr
				if a, err = netip.ParseAddr(rec[iRed]); err == nil {
					p = netip.PrefixFrom(a, a.BitLen())
				}
			}
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(strings.TrimPrefix(rec[iASN], "AS"))
			if err != nil {
				return fmt.Errorf("asn %q: %w", rec[iASN], err)
			}
			lo := u32(p.Masked().Addr())
			hi := lo | uint32(uint64(1)<<(32-p.Bits())-1)
			asignar(lo, hi, infoASN{n, rec[iNom], "IPinfo"})
		}
	})
}

// DB-IP ASN Lite: CSV sin encabezado: ip_inicio,ip_fin,asn,nombre (IPv4 e IPv6).
func recorrerDBIP(ruta string, asignar func(lo, hi uint32, info infoASN)) error {
	return recorrerCSVgz(ruta, func(r *csv.Reader) error {
		r.FieldsPerRecord = 4
		for {
			rec, err := r.Read()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if strings.Contains(rec[0], ":") {
				continue
			}
			lo, err1 := netip.ParseAddr(rec[0])
			hi, err2 := netip.ParseAddr(rec[1])
			n, err3 := strconv.Atoi(rec[2])
			if err := errors.Join(err1, err2, err3); err != nil {
				return fmt.Errorf("fila %q: %w", rec, err)
			}
			if n != 0 {
				asignar(u32(lo), u32(hi), infoASN{n, rec[3], "DB-IP"})
			}
		}
	})
}

func recorrerCSVgz(ruta string, fn func(*csv.Reader) error) error {
	f, err := os.Open(ruta)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", ruta, err)
	}
	defer gz.Close()
	r := csv.NewReader(gz)
	r.ReuseRecord = true
	if err := fn(r); err != nil {
		return fmt.Errorf("%s: %w", ruta, err)
	}
	return nil
}
