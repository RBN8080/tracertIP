package main

// BGP (0.5): prefijo y ASN de origen de cada destino, y los anuncios y
// retiros que RIPE RIS vio para ese prefijo en la ventana, via RIPEstat
// [RIPESTAT]. Las respuestas se guardan en la carpeta privada (evidencia, P2)
// y se reusan; una que no cubria toda la ventana (RIS publica con horas de
// retraso) se vuelve a pedir.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	baseRIPEstat  = "https://stat.ripe.net/data/"
	appRIPEstat   = "tracertip"           // sourceapp: RIPEstat pide identificar la aplicacion
	plazoRIPEstat = 120 * time.Second     // por consulta: toda E/S con plazo (P5)
	pausaRIPEstat = time.Second           // entre consultas, por cortesia con el servicio
	margenFinRIS  = time.Minute           // si los datos acaban antes de fin - margen, estan incompletos
	formatoRIS    = "2006-01-02T15:04:05" // RIPEstat: UTC, sin zona
)

// eventoBGP: un anuncio ("A") o retiro ("W") que un colector de RIS registro.
type eventoBGP struct {
	T    time.Time
	Tipo string
}

type fuenteBGP interface {
	// prefijo: el prefijo anunciado que cubre la IP y su ASN de origen;
	// "" si no esta anunciado.
	prefijo(ip string) (string, []int, error)
	// actualizaciones del prefijo entre desde y hasta, y hasta donde llegan
	// los datos de RIS.
	actualizaciones(pref string, desde, hasta time.Time) ([]eventoBGP, time.Time, error)
}

type ripestat struct {
	base, cache string
	cliente     *http.Client
	pausa       time.Duration
	ultima      time.Time
}

func nuevoRIPEstat(cache string) *ripestat {
	return &ripestat{base: baseRIPEstat, cache: cache, cliente: &http.Client{Timeout: plazoRIPEstat}, pausa: pausaRIPEstat}
}

// obtener devuelve la respuesta guardada si existe y aceptable la da por
// buena; si no, la pide a RIPEstat y la guarda.
func (r *ripestat) obtener(nombre, consulta string, aceptable func([]byte) bool) ([]byte, error) {
	ruta := filepath.Join(r.cache, nombre)
	if b, err := os.ReadFile(ruta); err == nil && aceptable(b) {
		return b, nil
	}
	if espera := r.pausa - time.Since(r.ultima); espera > 0 {
		time.Sleep(espera)
	}
	r.ultima = time.Now()
	resp, err := r.cliente.Get(r.base + consulta)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPEstat %s: HTTP %d", consulta, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(r.cache, 0o755); err != nil {
		return nil, err
	}
	return b, os.WriteFile(ruta, b, 0o644)
}

func archivo(partes ...string) string {
	return strings.NewReplacer("/", "_", ":", "_").Replace(strings.Join(partes, "_")) + ".json"
}

func (r *ripestat) prefijo(ip string) (string, []int, error) {
	q := "prefix-overview/data.json?resource=" + url.QueryEscape(ip) + "&sourceapp=" + appRIPEstat
	b, err := r.obtener(archivo("prefix-overview", ip), q, func([]byte) bool { return true })
	if err != nil {
		return "", nil, err
	}
	var v struct {
		Status string `json:"status"`
		Data   struct {
			Resource  string `json:"resource"`
			Announced bool   `json:"announced"`
			ASNs      []struct {
				ASN int `json:"asn"`
			} `json:"asns"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", nil, fmt.Errorf("prefix-overview %s: %w", ip, err)
	}
	if v.Status != "ok" {
		return "", nil, fmt.Errorf("prefix-overview %s: estado %q", ip, v.Status)
	}
	if !v.Data.Announced {
		return "", nil, nil
	}
	var origen []int
	for _, a := range v.Data.ASNs {
		origen = append(origen, a.ASN)
	}
	return v.Data.Resource, origen, nil
}

type respuestaUpdates struct {
	Status string `json:"status"`
	Data   struct {
		QueryEnd string `json:"query_endtime"`
		Updates  []struct {
			Type      string `json:"type"`
			Timestamp string `json:"timestamp"`
		} `json:"updates"`
	} `json:"data"`
}

func leerUpdates(b []byte) (respuestaUpdates, time.Time, error) {
	var v respuestaUpdates
	if err := json.Unmarshal(b, &v); err != nil {
		return v, time.Time{}, err
	}
	if v.Status != "ok" {
		return v, time.Time{}, fmt.Errorf("estado %q", v.Status)
	}
	fin, err := time.Parse(formatoRIS, v.Data.QueryEnd)
	return v, fin, err
}

func (r *ripestat) actualizaciones(pref string, desde, hasta time.Time) ([]eventoBGP, time.Time, error) {
	d, h := desde.UTC().Format(formatoRIS), hasta.UTC().Format(formatoRIS)
	q := "bgp-updates/data.json?resource=" + url.QueryEscape(pref) + "&starttime=" + d + "&endtime=" + h + "&sourceapp=" + appRIPEstat
	completa := func(b []byte) bool {
		_, fin, err := leerUpdates(b)
		return err == nil && !fin.Before(hasta.Add(-margenFinRIS))
	}
	b, err := r.obtener(archivo("bgp-updates", pref, d, h), q, completa)
	if err != nil {
		return nil, time.Time{}, err
	}
	v, fin, err := leerUpdates(b)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bgp-updates %s: %w", pref, err)
	}
	ev := make([]eventoBGP, 0, len(v.Data.Updates))
	for _, u := range v.Data.Updates {
		t, err := time.Parse(formatoRIS, u.Timestamp)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("bgp-updates %s: %w", pref, err)
		}
		ev = append(ev, eventoBGP{t, u.Type})
	}
	return ev, fin, nil
}

// cruzarBGP marca cada cambio de ruta ASN (12.1, "cambio con BGP"): "si" si
// RIS vio algun anuncio o retiro del prefijo entre el inicio de la traza
// anterior y el final de la traza del cambio; "no" si no; "sin datos" si ese
// final pasa del fin de los datos de RIS.
func cruzarBGP(cs []cambio, ev []eventoBGP, finDatos time.Time) {
	for i := range cs {
		c := &cs[i]
		hasta := c.Despues.Add(duracionTraza)
		if hasta.After(finDatos) {
			c.BGP = "sin datos"
			continue
		}
		c.BGP = "no"
		for _, e := range ev {
			if e.T.After(c.Antes) && !e.T.After(hasta) {
				c.BGP = "si"
				break
			}
		}
	}
}

func consultarBGP(f fuenteBGP, inf *informe, inicio, fin time.Time) error {
	type resultado struct {
		ev  []eventoBGP
		fin time.Time
	}
	porPrefijo := map[string]resultado{}
	for i := range inf.Destinos {
		e := &inf.Destinos[i]
		pref, origen, err := f.prefijo(e.IP)
		if err != nil {
			return fmt.Errorf("BGP de %s: %w", e.IP, err)
		}
		e.Prefijo, e.Origen = pref, origen
		if pref == "" {
			continue
		}
		r, ok := porPrefijo[pref]
		if !ok {
			if r.ev, r.fin, err = f.actualizaciones(pref, inicio, fin); err != nil {
				return fmt.Errorf("BGP de %s (%s): %w", e.IP, pref, err)
			}
			porPrefijo[pref] = r
		}
		e.FinBGP = r.fin
		for _, x := range r.ev {
			switch x.Tipo {
			case "A":
				e.Anuncios++
			case "W":
				e.Retiros++
			}
		}
		cruzarBGP(e.Cambios, r.ev, r.fin)
		if inf.FinBGP.IsZero() || r.fin.Before(inf.FinBGP) {
			inf.FinBGP = r.fin
		}
	}
	inf.BGP = true
	return nil
}
