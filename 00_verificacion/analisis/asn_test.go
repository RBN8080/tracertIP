package main

import (
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func escribirGz(t *testing.T, ruta, contenido string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(ruta)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte(contenido)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

const encIPinfo = "network,country,country_code,continent,continent_code,asn,as_name,as_domain\n"

func TestResolverASN(t *testing.T) {
	dir := t.TempDir()
	ipinfo, dbip := filepath.Join(dir, "ipinfo.csv.gz"), filepath.Join(dir, "dbip.csv.gz")
	escribirGz(t, ipinfo, encIPinfo+
		"192.0.2.0/25,Ejemplo,EX,Ejemplo,EX,AS64500,\"Red, de ejemplo\",example.com\n"+
		"192.0.2.128/25,Ejemplo,EX,Ejemplo,EX,,,\n"+
		"2001:db8::/32,Ejemplo,EX,Ejemplo,EX,AS64501,Solo IPv6,example.com\n"+
		"198.51.100.0/24,Ejemplo,EX,Ejemplo,EX,AS64502,Otra,example.com\n"+
		"203.0.113.130,Ejemplo,EX,Ejemplo,EX,AS64503,IP suelta,example.com\n") // 126 719 filas asi en el archivo real
	escribirGz(t, dbip, "192.0.2.0,192.0.2.255,64510,\"Respaldo\"\n"+
		"2001:db8::,2001:db8::ffff,64511,Solo IPv6\n"+
		"203.0.113.0,203.0.113.127,64512,\"Solo en DB-IP\"\n")
	var buscadas []netip.Addr
	for _, h := range []string{"192.0.2.5", "192.0.2.200", "198.51.100.77", "203.0.113.5", "203.0.113.130", "203.0.113.131", "203.0.113.200"} {
		buscadas = append(buscadas, netip.MustParseAddr(h))
	}
	tab, err := resolverASN(buscadas, ipinfo, dbip)
	if err != nil {
		t.Fatal(err)
	}
	quiero := map[string]infoASN{
		"192.0.2.5":     {64500, "Red, de ejemplo", "IPinfo"}, // IPinfo manda sobre DB-IP
		"192.0.2.200":   {64510, "Respaldo", "DB-IP"},         // IPinfo sin ASN: DB-IP
		"198.51.100.77": {64502, "Otra", "IPinfo"},
		"203.0.113.5":   {64512, "Solo en DB-IP", "DB-IP"},
		"203.0.113.130": {64503, "IP suelta", "IPinfo"}, // fila sin "/": una sola direccion
		"203.0.113.131": {},                             // la vecina no esta en esa fila
		"203.0.113.200": {},                             // en ninguna: AS?
	}
	for h, q := range quiero {
		if i := tab.de(h); i != q {
			t.Errorf("%s: %+v; quiero %+v", h, i, q)
		}
	}
	escribirGz(t, ipinfo, "red,asn\n192.0.2.0/24,AS64500\n")
	if _, err := resolverASN(buscadas, ipinfo, dbip); err == nil {
		t.Error("un encabezado de IPinfo inesperado deberia fallar")
	}
}
