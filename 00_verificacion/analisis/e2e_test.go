package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// bgpFalso sustituye a RIPEstat en la prueba de punta a punta.
type bgpFalso struct {
	prefijos map[string]string
	eventos  map[string][]eventoBGP
	fin      time.Time
}

func (f *bgpFalso) prefijo(ip string) (string, []int, error) {
	if p := f.prefijos[ip]; p != "" {
		return p, []int{64510}, nil
	}
	return "", nil, nil
}

func (f *bgpFalso) actualizaciones(pref string, _, _ time.Time) ([]eventoBGP, time.Time, error) {
	return f.eventos[pref], f.fin, nil
}

// carpetaPrivada arma una carpeta privada inventada con 48 h de datos: 3
// destinos (2 originales), una corrida ausente (k=50), una incompleta (k=60),
// una traza que no llega (k=70) y, si cambio, una ruta nueva desde k=100.
func carpetaPrivada(t *testing.T, inicio time.Time, cambio, caliente bool) string {
	t.Helper()
	priv := t.TempDir()
	escribir(t, filepath.Join(priv, "inventario.txt"), "   ISP .................. Ejemplo, AS64500   [medido]\n")
	escribir(t, filepath.Join(priv, "nodo", "destinos.conf"),
		"# -- originales (punto de aborto)\n192.0.2.10\n192.0.2.20\n# -- Europa\n198.51.100.30\n")
	// Limite fisico: 192.0.2.10 en las antipodas (imposible a ~100 ms), 192.0.2.20
	// a 10 grados (posible) y 198.51.100.30 sin ubicacion declarada (NA).
	escribir(t, filepath.Join(priv, "origen.json"), `{"lat":0,"lon":0}`)
	escribir(t, filepath.Join(priv, "ubicaciones.tsv"), "192.0.2.10\t0,180\tprueba\n192.0.2.20\t0,10\tprueba\n")
	escribirGz(t, filepath.Join(priv, "datos", "ipinfo", "ipinfo_lite.csv.gz"), encIPinfo+
		"203.0.113.0/26,Ejemplo,EX,Ejemplo,EX,AS64500,Acceso de ejemplo,example.com\n"+
		"203.0.113.64/26,Ejemplo,EX,Ejemplo,EX,AS64501,Transito A,example.com\n"+
		"203.0.113.128/26,Ejemplo,EX,Ejemplo,EX,AS64502,Transito B,example.com\n"+
		"192.0.2.0/24,Ejemplo,EX,Ejemplo,EX,AS64510,Destino,example.com\n")
	escribirGz(t, filepath.Join(priv, "datos", "dbip", "dbip-asn-lite-2026-01.csv.gz"),
		"198.51.100.0,198.51.100.255,64511,\"Destino Europa\"\n")

	hub := func(n int, host string, avg float64) map[string]any {
		loss := 0.0
		if host == mudo {
			loss, avg = 100, 0
		}
		return map[string]any{"count": n, "host": host, "Loss%": loss, "Snt": 10, "Last": avg, "Avg": avg, "Best": avg - 0.2, "Wrst": avg + 0.5, "StDev": 0.1}
	}
	var mtr, salud strings.Builder
	for k := range 192 {
		t0 := inicio.Add(time.Duration(k)*periodoCorrida + 5*time.Second)
		for i := range 3 {
			fmt.Fprintf(&salud, `{"t":%q,"temp_mc":%d,"throttled":"0x0","subtension":0,"carga1":0.05,"ntp_offset":"-1.5ms"}`+"\n",
				t0.Add(time.Duration(i)*5*time.Minute).Format(time.RFC3339), map[bool]int{true: 76000, false: 55000}[caliente && k == 120])
		}
		if k == 50 {
			continue
		}
		for i, d := range []string{"192.0.2.10", "192.0.2.20", "198.51.100.30"} {
			if k == 60 && i == 2 {
				continue
			}
			avg := 100 + 0.1*float64(k%10)
			ruta := []string{ip4(192, 168, 1, 1), ip4(100, 64, 0, 1), "203.0.113.1", mudo, "203.0.113.65"}
			switch {
			case i == 0 && cambio && k >= 100:
				ruta[4] = "203.0.113.130"
			case i == 2:
				ruta = append(ruta, "203.0.113.200") // sin ASN en ninguna base: AS?
			}
			ruta = append(ruta, d)
			if i == 1 && k == 70 {
				ruta[len(ruta)-1] = mudo // no llega: traza no valida
			}
			var hubs []map[string]any
			for n, h := range ruta {
				hubs = append(hubs, hub(n+1, h, avg*float64(n+1)/float64(len(ruta))))
			}
			b, err := json.Marshal(map[string]any{
				"t": t0.Format(time.RFC3339), "t_destino": t0.Add(time.Duration(i) * duracionTraza).Format(time.RFC3339), "destino": d,
				"mtr": map[string]any{"report": map[string]any{"mtr": map[string]any{"src": "nodo", "dst": d}, "hubs": hubs}},
			})
			if err != nil {
				t.Fatal(err)
			}
			mtr.Write(append(b, '\n'))
		}
	}
	dir := filepath.Join(priv, "datos", "recoleccion")
	escribir(t, filepath.Join(dir, "mtr-2026-01-05.jsonl"), mtr.String())
	escribir(t, filepath.Join(dir, "salud-2026-01-05.jsonl"), salud.String())
	escribir(t, filepath.Join(dir, "vigia-2026-01-05.jsonl"),
		fmt.Sprintf(`{"corrida":%q,"estado":"ok","motivos":""}`+"\n"+`{"corrida":%q,"estado":"alerta","motivos":"corrida incompleta: 2 de 3 trazas"}`+"\n",
			inicio.Add(5*time.Second).Format(time.RFC3339), inicio.Add(60*periodoCorrida+5*time.Second).Format(time.RFC3339)))
	return priv
}

func TestAnalizarDePuntaAPunta(t *testing.T) {
	inicio := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	casos := []struct {
		nombre                   string
		cambio, caliente         bool
		cambios                  int
		aborto, enfriar          bool
		consecuencia, frio, bgp1 string
	}{
		{"ruta nueva y calor", true, true, 1, false, true, "F1 y después F2", "Revisar el enfriamiento es requisito antes de F2", "si"},
		{"estable y fresco", false, false, 0, true, false, "Aborto parcial", "Nada que revisar", ""},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			priv := carpetaPrivada(t, inicio, c.cambio, c.caliente)
			bgp := &bgpFalso{
				prefijos: map[string]string{"192.0.2.10": "192.0.2.0/24", "192.0.2.20": "192.0.2.0/24", "198.51.100.30": "198.51.100.0/24"},
				eventos:  map[string][]eventoBGP{"192.0.2.0/24": {{inicio.Add(100 * periodoCorrida), "A"}}},
				fin:      inicio.Add(45 * time.Hour),
			}
			inf, err := analizar(priv, inicio, bgp)
			if err != nil {
				t.Fatal(err)
			}
			cob := inf.Cob
			if cob.Ranuras != 192 || cob.Completas != 190 || len(cob.Huecos) != 2 || cob.Huecos[0].Trazas != 0 || cob.Huecos[1].Trazas != 2 {
				t.Errorf("cobertura: %d ranuras, %d completas, huecos %+v", cob.Ranuras, cob.Completas, cob.Huecos)
			}
			d1, d2, d3 := inf.Destinos[0], inf.Destinos[1], inf.Destinos[2]
			if d1.Validas != 191 || d2.Obtenidas != 191 || d2.Validas != 190 || d3.Obtenidas != 190 {
				t.Errorf("validas/obtenidas: %d, %d/%d, %d", d1.Validas, d2.Validas, d2.Obtenidas, d3.Obtenidas)
			}
			if d3.RutaDominante != "AS64501 AS? AS64511" || d3.ConASDesconocido != 190 {
				t.Errorf("destino con AS? y ASN de DB-IP: %q, %d", d3.RutaDominante, d3.ConASDesconocido)
			}
			if inf.ASN.DBIP != 1 || inf.ASN.Desconocidas != 1 {
				t.Errorf("ASN: %+v", inf.ASN)
			}
			if len(d1.Cambios) != c.cambios || (c.cambios > 0 && (d1.Cambios[0].BGP != c.bgp1 || d1.Cambios[0].A != "AS64502 AS64510")) {
				t.Errorf("cambios del destino 1: %+v", d1.Cambios)
			}
			if d1.Anuncios != 1 || d3.Anuncios != 0 || !inf.FinBGP.Equal(bgp.fin) {
				t.Errorf("BGP: anuncios %d y %d, fin %v", d1.Anuncios, d3.Anuncios, inf.FinBGP)
			}
			if !d1.Fisica.Imposible() || !d2.Fisica.Evaluable || d2.Fisica.Imposible() || d3.Fisica.Evaluable {
				t.Errorf("limite fisico: %+v, %+v, %+v", d1.Fisica, d2.Fisica, d3.Fisica)
			}
			v := inf.Veredicto
			if v.Originales != 2 || v.Cambios != c.cambios || v.Aborto != c.aborto || v.Enfriamiento != c.enfriar || v.JitterMax >= umbralJitterMs {
				t.Errorf("veredicto %+v", v)
			}
			md := inf.markdown()
			for _, s := range []string{c.consecuencia, c.frio, "### originales (punto de aborto)", "| AS64511 | Destino Europa |", "corrida incompleta: 2 de 3 trazas", "⛔ imposible"} {
				if !strings.Contains(md, s) {
					t.Errorf("el informe no dice %q", s)
				}
			}
		})
	}
}

func TestAnalizarSinGrupoDeAborto(t *testing.T) {
	inicio := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	priv := carpetaPrivada(t, inicio, false, false)
	escribir(t, filepath.Join(priv, "nodo", "destinos.conf"), "# -- Europa\n198.51.100.30\n")
	if _, err := analizar(priv, inicio, nil); err == nil {
		t.Error("sin el grupo de los originales no se puede decidir el aborto: deberia fallar")
	}
}
