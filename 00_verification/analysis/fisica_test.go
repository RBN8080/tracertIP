package main

import (
	"math"
	"path/filepath"
	"testing"
)

func TestDistanciaKm(t *testing.T) {
	casos := []struct {
		nombre      string
		a, b        coord
		quiero, tol float64
	}{
		{"mismo punto", coord{10, 20}, coord{10, 20}, 0, 0.001},
		{"un grado de ecuador", coord{0, 0}, coord{0, 1}, 111.19, 0.01},
		{"antipodas", coord{0, 0}, coord{0, 180}, 20015.09, 0.01},
	}
	for _, c := range casos {
		if d := distanciaKm(c.a, c.b); math.Abs(d-c.quiero) > c.tol {
			t.Errorf("%s: %.2f km, quiero %.2f", c.nombre, d, c.quiero)
		}
	}
}

func TestLimiteFisico(t *testing.T) {
	casos := []struct {
		nombre    string
		best      float64
		hay       bool
		dest      coord
		conUbic   bool
		razon     float64
		evaluable bool
		imposible bool
	}{
		{"sin ubicacion declarada: NA", 100, true, coord{}, false, 0, false, false},
		{"sin RTT: NA, nunca 0", 0, false, coord{0, 1}, true, 0, false, false},
		{"lejos y lento: posible", 50, true, coord{0, 10}, true, 50 / (2 * 1111.95 / velFibraKmMs), true, false},
		{"mas rapido que la luz en fibra: imposible", 99.8, true, coord{0, 180}, true, 99.8 / (2 * 20015.09 / velFibraKmMs), true, true},
	}
	for _, c := range casos {
		l := limiteFisico(c.best, c.hay, coord{0, 0}, c.dest, c.conUbic)
		if l.Evaluable != c.evaluable || l.Imposible() != c.imposible || (c.evaluable && math.Abs(l.Razon-c.razon) > 0.001) {
			t.Errorf("%s: %+v (imposible=%v)", c.nombre, l, l.Imposible())
		}
	}
}

func TestLeerUbicaciones(t *testing.T) {
	priv := t.TempDir()
	escribir(t, filepath.Join(priv, "origen.json"), `{"ciudad":"Ejemplo","lat":1.5,"lon":-2.5}`)
	escribir(t, filepath.Join(priv, "ubicaciones.tsv"),
		"# ip\tlat,lon\tfuente\r\n192.0.2.10\t-33.8688,151.2093\tejemplo\r\n\r\n")
	o, u, err := leerUbicaciones(priv)
	if err != nil || o != (coord{1.5, -2.5}) || len(u) != 1 || u["192.0.2.10"] != (coord{-33.8688, 151.2093}) {
		t.Fatalf("origen %+v, ubicaciones %+v, err %v", o, u, err)
	}
	for _, malo := range []string{"192.0.2.10\t91,0\tx\n", "192.0.2.10\tsin coma\tx\n", "no-ip\t0,0\tx\n", "192.0.2.10\t0,0\tx\n192.0.2.10\t1,1\tx\n"} {
		escribir(t, filepath.Join(priv, "ubicaciones.tsv"), malo)
		if _, _, err := leerUbicaciones(priv); err == nil {
			t.Errorf("%q deberia fallar", malo)
		}
	}
}
