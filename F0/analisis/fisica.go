package main

// Limite fisico por destino (00_IDEA.txt, H2 y H3): con el RTT minimo medido,
// el destino no puede estar mas lejos de lo que la luz en fibra recorre ida y
// vuelta. Si su ubicacion declarada esta mas lejos, la declaracion es falsa
// (proxy, anycast o geolocalizacion erronea). El metodo solo delata un
// servidor MAS CERCA de lo declarado; uno mas lejos no viola nada (P2).

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	radioTierraKm = 6371.0             // radio medio (IUGG)
	velFibraKmMs  = 299.792458 / 1.468 // c en km/ms entre el indice de refraccion de la fibra: ~204.2 km/ms
)

type coord struct{ Lat, Lon float64 }

// distanciaKm: gran circulo (haversine).
func distanciaKm(a, b coord) float64 {
	r := math.Pi / 180
	dLat, dLon := (b.Lat-a.Lat)*r, (b.Lon-a.Lon)*r
	h := math.Pow(math.Sin(dLat/2), 2) + math.Cos(a.Lat*r)*math.Cos(b.Lat*r)*math.Pow(math.Sin(dLon/2), 2)
	return 2 * radioTierraKm * math.Atan2(math.Sqrt(h), math.Sqrt(1-h))
}

// fisica: Razon = RTT minimo medido / RTT minimo fisico. Sin ubicacion o sin
// RTT no es evaluable: NA, nunca 0 (P5).
type fisica struct {
	Evaluable bool
	Km, MinMs float64
	Razon     float64
}

func (f fisica) Imposible() bool { return f.Evaluable && f.Razon < 1 }

func limiteFisico(bestMin float64, hayRTT bool, origen, dest coord, conUbic bool) fisica {
	if !hayRTT || !conUbic {
		return fisica{}
	}
	km := distanciaKm(origen, dest)
	minMs := 2 * km / velFibraKmMs
	if minMs == 0 {
		return fisica{}
	}
	return fisica{Evaluable: true, Km: km, MinMs: minMs, Razon: bestMin / minMs}
}

// leerUbicaciones: el origen real (origen.json) y la ubicacion declarada de
// cada destino (ubicaciones.tsv: "ip<TAB>lat,lon<TAB>fuente", # comenta), ambos
// en la carpeta privada. Un destino sin fila queda NA; una fila mala falla.
func leerUbicaciones(privado string) (coord, map[string]coord, error) {
	var o struct{ Lat, Lon *float64 }
	ro := filepath.Join(privado, "origen.json")
	b, err := os.ReadFile(ro)
	if err != nil {
		return coord{}, nil, err
	}
	if err := json.Unmarshal(b, &o); err != nil || o.Lat == nil || o.Lon == nil {
		return coord{}, nil, fmt.Errorf("%s: falta lat o lon (%v)", ro, err)
	}
	origen := coord{*o.Lat, *o.Lon}
	ru := filepath.Join(privado, "ubicaciones.tsv")
	b, err = os.ReadFile(ru)
	if err != nil {
		return coord{}, nil, err
	}
	u := map[string]coord{}
	for i, l := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		c := strings.Split(l, "\t")
		mal := func(por string) error { return fmt.Errorf("%s:%d: %s", ru, i+1, por) }
		if len(c) < 2 {
			return coord{}, nil, mal("faltan columnas")
		}
		a, err := netip.ParseAddr(strings.TrimSpace(c[0]))
		if err != nil {
			return coord{}, nil, mal("no es una IP")
		}
		ll := strings.Split(c[1], ",")
		if len(ll) != 2 {
			return coord{}, nil, mal("se espera lat,lon")
		}
		lat, e1 := strconv.ParseFloat(strings.TrimSpace(ll[0]), 64)
		lon, e2 := strconv.ParseFloat(strings.TrimSpace(ll[1]), 64)
		if e1 != nil || e2 != nil || math.Abs(lat) > 90 || math.Abs(lon) > 180 {
			return coord{}, nil, mal("coordenadas fuera de rango")
		}
		if _, ya := u[a.String()]; ya {
			return coord{}, nil, mal("IP repetida")
		}
		u[a.String()] = coord{lat, lon}
	}
	return origen, u, nil
}
