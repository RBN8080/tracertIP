package main

// Lectura de lo recolectado en 0.2 y de los ajustes privados. Lo que no se
// puede decodificar se cuenta y se informa (P5): no se descarta en silencio.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// salto es una entrada de "hubs" en la salida JSON de mtr 0.96. Las llaves
// se leyeron de trazas reales el 2026-09-26 (tambien trae Last y StDev).
type salto struct {
	Count int     `json:"count"`
	Host  string  `json:"host"`
	Loss  float64 `json:"Loss%"`
	Snt   int     `json:"Snt"`
	Avg   float64 `json:"Avg"`
	Best  float64 `json:"Best"`
	Wrst  float64 `json:"Wrst"`
}

// traza es una linea de mtr-*.jsonl: un destino en una corrida.
type traza struct {
	T        time.Time // inicio de la corrida
	TDestino time.Time // inicio de esta traza (t_destino; si falta, t)
	Destino  string
	Saltos   []salto // nil: mtr no produjo salida ("mtr": null)
}

// lectura cuenta lo leido de un tipo de archivo. Lineas = dentro de la
// ventana; Ilegibles = lineas que no se pudieron decodificar.
type lectura struct {
	Archivos, Lineas, Ilegibles int
}

func enVentana(t, desde, hasta time.Time) bool { return !t.Before(desde) && t.Before(hasta) }

// leerJSONL pasa a fn cada linea no vacia de los archivos que casan con
// patron. fn dice si la linea cae dentro de la ventana.
func leerJSONL(patron string, fn func([]byte) (bool, error)) (lectura, error) {
	var l lectura
	archivos, err := filepath.Glob(patron)
	if err != nil {
		return l, err
	}
	sort.Strings(archivos)
	l.Archivos = len(archivos)
	for _, a := range archivos {
		if err := leerArchivo(a, fn, &l); err != nil {
			return l, err
		}
	}
	return l, nil
}

func leerArchivo(ruta string, fn func([]byte) (bool, error), l *lectura) error {
	f, err := os.Open(ruta)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20) // una traza de 40 saltos ocupa ~6 KB
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		dentro, err := fn(b)
		switch {
		case err != nil:
			l.Ilegibles++
		case dentro:
			l.Lineas++
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", ruta, err)
	}
	return nil
}

func leerTrazas(patron string, desde, hasta time.Time) ([]traza, lectura, error) {
	var out []traza
	l, err := leerJSONL(patron, func(b []byte) (bool, error) {
		var v struct {
			T        string `json:"t"`
			TDestino string `json:"t_destino"`
			Destino  string `json:"destino"`
			Mtr      *struct {
				Report struct {
					Hubs []salto `json:"hubs"`
				} `json:"report"`
			} `json:"mtr"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return false, err
		}
		t, err := time.Parse(time.RFC3339, v.T)
		if err != nil {
			return false, err
		}
		if !enVentana(t, desde, hasta) {
			return false, nil
		}
		td := t
		if v.TDestino != "" {
			if td, err = time.Parse(time.RFC3339, v.TDestino); err != nil {
				return false, err
			}
		}
		if _, err := netip.ParseAddr(v.Destino); err != nil {
			return false, err
		}
		tr := traza{T: t, TDestino: td, Destino: v.Destino}
		if v.Mtr != nil {
			tr.Saltos = append([]salto{}, v.Mtr.Report.Hubs...)
		}
		out = append(out, tr)
		return true, nil
	})
	return out, l, err
}

// muestraSalud es una linea de salud-*.jsonl. Lo no medido llega como null
// (temperatura, subtension) o como "NA" (throttled, desfase NTP).
type muestraSalud struct {
	T          time.Time
	TempMC     *float64
	Throttled  string
	Subtension *float64
	NTP        string
}

func leerSalud(patron string, desde, hasta time.Time) ([]muestraSalud, lectura, error) {
	var out []muestraSalud
	l, err := leerJSONL(patron, func(b []byte) (bool, error) {
		var v struct {
			T          string   `json:"t"`
			TempMC     *float64 `json:"temp_mc"`
			Throttled  string   `json:"throttled"`
			Subtension *float64 `json:"subtension"`
			NTP        string   `json:"ntp_offset"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return false, err
		}
		t, err := time.Parse(time.RFC3339, v.T)
		if err != nil {
			return false, err
		}
		if !enVentana(t, desde, hasta) {
			return false, nil
		}
		out = append(out, muestraSalud{t, v.TempMC, v.Throttled, v.Subtension, v.NTP})
		return true, nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].T.Before(out[j].T) })
	return out, l, err
}

// veredictoVigia es una linea de vigia-*.jsonl (vigilar.sh).
type veredictoVigia struct {
	Corrida time.Time
	Estado  string
	Motivos string
}

func leerVigia(patron string, desde, hasta time.Time) ([]veredictoVigia, lectura, error) {
	var out []veredictoVigia
	l, err := leerJSONL(patron, func(b []byte) (bool, error) {
		var v struct {
			Corrida string `json:"corrida"`
			Estado  string `json:"estado"`
			Motivos string `json:"motivos"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return false, err
		}
		t, err := time.Parse(time.RFC3339, v.Corrida)
		if err != nil {
			return false, err
		}
		if !enVentana(t, desde, hasta) {
			return false, nil
		}
		out = append(out, veredictoVigia{t, v.Estado, v.Motivos})
		return true, nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Corrida.Before(out[j].Corrida) })
	return out, l, err
}

// destino es una IP de destinos.conf y su grupo: el de la linea "# -- <grupo>"
// mas reciente (lo que sigue a " (" es comentario).
type destino struct {
	IP, Grupo string
}

func leerDestinos(ruta string) ([]destino, error) {
	b, err := os.ReadFile(ruta)
	if err != nil {
		return nil, err
	}
	var out []destino
	visto := map[string]bool{}
	grupo := "sin grupo"
	for i, linea := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		l := strings.TrimSpace(linea)
		switch {
		case strings.HasPrefix(l, "# --"):
			g := strings.TrimSpace(strings.TrimPrefix(l, "# --"))
			if j := strings.Index(g, " ("); j >= 0 {
				g = g[:j]
			}
			if g != "" {
				grupo = g
			}
		case l == "" || strings.HasPrefix(l, "#"):
		default:
			a, err := netip.ParseAddr(l)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %q no es una IP suelta", ruta, i+1, l)
			}
			if visto[a.String()] {
				return nil, fmt.Errorf("%s:%d: %s esta repetida", ruta, i+1, a)
			}
			visto[a.String()] = true
			out = append(out, destino{a.String(), grupo})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: sin destinos", ruta)
	}
	return out, nil
}

// El ASN del ISP de acceso sale de la linea "ISP ... AS<n>" del inventario
// privado. Tiene que haber exactamente una: adivinarlo seria peor (P5).
var reISP = regexp.MustCompile(`(?m)^\s*ISP\b.*\bAS(\d+)\b`)

func leerASNAcceso(ruta string) (int, error) {
	b, err := os.ReadFile(ruta)
	if err != nil {
		return 0, err
	}
	m := reISP.FindAllSubmatch(b, -1)
	if len(m) != 1 {
		return 0, fmt.Errorf("%s: se esperaba una linea 'ISP ... AS<n>' y hay %d", ruta, len(m))
	}
	return strconv.Atoi(string(m[0][1]))
}
