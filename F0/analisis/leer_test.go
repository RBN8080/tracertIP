package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// La muestra sintetica de la instruccion (8.5): la estructura real de
// mtr --json con valores inventados.
func TestMuestraMtr(t *testing.T) {
	desde := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	trs, l, err := leerTrazas(filepath.Join("testdata", "mtr-muestra.jsonl"), desde, desde.Add(duracionVentana))
	if err != nil {
		t.Fatal(err)
	}
	if l.Archivos != 1 || l.Lineas != 2 || l.Ilegibles != 0 || len(trs) != 2 {
		t.Fatalf("lectura %+v, %d trazas; quiero 1 archivo, 2 lineas en la ventana y 0 ilegibles", l, len(trs))
	}
	a, b := trs[0], trs[1]
	if len(a.Saltos) != 4 || !a.valida() || a.Saltos[1].Host != mudo || a.Saltos[1].Loss != 100 {
		t.Errorf("traza valida mal leida: %+v", a)
	}
	if f := a.Saltos[3]; f.Avg != 150.63 || f.Best != 150.104 || f.Wrst != 151.902 || f.Snt != 10 || f.Count != 4 {
		t.Errorf("salto destino mal leido: %+v", f)
	}
	if b.Saltos != nil || b.valida() || !b.TDestino.Equal(desde.Add(29*time.Second)) {
		t.Errorf("traza con mtr nulo mal leida: %+v", b)
	}
}

func TestLineaIlegible(t *testing.T) {
	dir := t.TempDir()
	escribir(t, filepath.Join(dir, "mtr-1.jsonl"), "{\"t\":\"2026-01-05T00:00:05Z\",\"destino\":\"192.0.2.1\",\"mtr\":null}\n{roto\n")
	desde := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	_, l, err := leerTrazas(filepath.Join(dir, "mtr-*.jsonl"), desde, desde.Add(time.Hour))
	if err != nil || l.Lineas != 1 || l.Ilegibles != 1 {
		t.Errorf("lectura %+v, %v; quiero 1 linea y 1 ilegible", l, err)
	}
}

func TestLeerDestinos(t *testing.T) {
	dir := t.TempDir()
	ruta := filepath.Join(dir, "destinos.conf")
	escribir(t, ruta, "# comentario\r\n# -- originales (se miden primero)\r\n192.0.2.10\r\n192.0.2.20\r\n# -- Europa\r\n198.51.100.30\r\n")
	d, err := leerDestinos(ruta)
	if err != nil {
		t.Fatal(err)
	}
	quiero := []destino{{"192.0.2.10", "originales"}, {"192.0.2.20", "originales"}, {"198.51.100.30", "Europa"}}
	if len(d) != len(quiero) {
		t.Fatalf("destinos %v; quiero %v", d, quiero)
	}
	for i := range d {
		if d[i] != quiero[i] {
			t.Errorf("destino %d = %v; quiero %v", i, d[i], quiero[i])
		}
	}
	for _, malo := range []string{"192.0.2.0/24\n", "192.0.2.1\n192.0.2.1\n", "# nada\n", "ejemplo.test\n"} {
		escribir(t, ruta, malo)
		if _, err := leerDestinos(ruta); err == nil {
			t.Errorf("leerDestinos(%q) deberia fallar", malo)
		}
	}
}

func TestLeerASNAcceso(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "inventario.txt")
	escribir(t, ruta, " RED\n   ISP .................. Ejemplo, AS64500      [medido]\n   Acceso ....... otra cosa AS64501\n")
	if n, err := leerASNAcceso(ruta); err != nil || n != 64500 {
		t.Errorf("leerASNAcceso = %d, %v; quiero 64500", n, err)
	}
	for _, malo := range []string{"sin la linea\n", "ISP a AS64500\nISP b AS64501\n"} {
		escribir(t, ruta, malo)
		if _, err := leerASNAcceso(ruta); err == nil {
			t.Errorf("leerASNAcceso(%q) deberia fallar", malo)
		}
	}
}

func escribir(t *testing.T, ruta, contenido string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}
