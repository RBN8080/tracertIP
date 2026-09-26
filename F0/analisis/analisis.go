package main

// Calculo del paso 0.5: cobertura, estadistica y huellas por destino, salud
// del nodo, cruce con BGP y veredicto. Las definiciones son las de la
// instruccion, 12.1; donde hubo que precisarlas, el comentario lo dice.

import (
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Bits de vcgencmd get_throttled.
const (
	bitsThrottledActivo  = 0x0000f // 0x1-0x8: subtension, limite de frecuencia o termico AHORA
	bitsThrottledOcurrio = 0xf0000 // 0x10000-0x80000: lo mismo, "ya ocurrio" desde el arranque
)

type informe struct {
	Generado  time.Time
	Cob       cobertura
	Grupos    []string       // en el orden de destinos.conf
	Destinos  []estadDestino // en el orden de destinos.conf
	Salud     resumenSalud
	Vigia     []veredictoVigia
	ASN       resumenASN
	BGP       bool      // se consulto RIPEstat
	FinBGP    time.Time // el menor fin de datos de RIS entre los prefijos
	Veredicto veredicto
}

type cobertura struct {
	Inicio, Fin       time.Time
	Ranuras           int // corridas esperadas por destino
	Completas         int
	Huecos            []hueco
	Trazas            int
	Mtr, Salud, Vigia lectura
	Ajenos            []string // destinos en los datos que no estan en destinos.conf
}

// hueco: una corrida esperada que falto entera o quedo incompleta.
type hueco struct {
	Ranura time.Time
	Trazas int
}

type resumenASN struct {
	IPinfo, DBIP, Desconocidas int
	ArchivoIPinfo, ArchivoDBIP string
	Nombres                    map[int]string
}

// analizar hace el paso 0.5 completo sobre la carpeta privada.
func analizar(privado string, inicio time.Time, bgp fuenteBGP) (*informe, error) {
	fin := inicio.Add(duracionVentana)
	dest, err := leerDestinos(filepath.Join(privado, "nodo", "destinos.conf"))
	if err != nil {
		return nil, err
	}
	hayGrupo := false
	for _, d := range dest {
		hayGrupo = hayGrupo || d.Grupo == grupoAborto
	}
	if !hayGrupo {
		return nil, fmt.Errorf("destinos.conf no tiene el grupo %q del punto de aborto", grupoAborto)
	}
	asnAcceso, err := leerASNAcceso(filepath.Join(privado, "inventario.txt"))
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(privado, "datos", "recoleccion")
	trazas, lm, err := leerTrazas(filepath.Join(dir, "mtr-*.jsonl"), inicio, fin)
	if err != nil {
		return nil, err
	}
	muestras, ls, err := leerSalud(filepath.Join(dir, "salud-*.jsonl"), inicio, fin)
	if err != nil {
		return nil, err
	}
	vigia, lv, err := leerVigia(filepath.Join(dir, "vigia-*.jsonl"), inicio, fin)
	if err != nil {
		return nil, err
	}
	if lm.Lineas == 0 {
		return nil, fmt.Errorf("no hay trazas de mtr en la ventana %s a %s", inicio.Format(time.RFC3339), fin.Format(time.RFC3339))
	}

	rutaIPinfo := filepath.Join(privado, "datos", "ipinfo", "ipinfo_lite.csv.gz")
	dbips, err := filepath.Glob(filepath.Join(privado, "datos", "dbip", "dbip-asn-lite-*.csv.gz"))
	if err != nil {
		return nil, err
	}
	if len(dbips) == 0 {
		return nil, fmt.Errorf("no hay datos/dbip/dbip-asn-lite-*.csv.gz")
	}
	sort.Strings(dbips)
	rutaDBIP := dbips[len(dbips)-1] // el mes mas reciente
	hosts := hostsPublicos(trazas)
	asn, err := resolverASN(hosts, rutaIPinfo, rutaDBIP)
	if err != nil {
		return nil, err
	}

	inf := &informe{
		Generado: time.Now().UTC(),
		Salud:    resumirSalud(muestras),
		Vigia:    vigia,
		ASN:      resumirASN(asn, hosts, filepath.Base(rutaIPinfo), filepath.Base(rutaDBIP)),
	}
	inf.Cob = cubrir(dest, trazas, inicio, fin)
	inf.Cob.Mtr, inf.Cob.Salud, inf.Cob.Vigia = lm, ls, lv

	porDestino := map[string][]traza{}
	for _, t := range trazas {
		porDestino[t.Destino] = append(porDestino[t.Destino], t)
	}
	for _, d := range dest {
		if len(inf.Grupos) == 0 || inf.Grupos[len(inf.Grupos)-1] != d.Grupo {
			inf.Grupos = append(inf.Grupos, d.Grupo)
		}
		inf.Destinos = append(inf.Destinos, estadisticas(d, porDestino[d.IP], asn, asnAcceso, inf.Cob.Ranuras))
	}
	if bgp != nil {
		if err := consultarBGP(bgp, inf, inicio, fin); err != nil {
			return nil, err
		}
	}
	inf.Veredicto = decidir(inf.Destinos, inf.Salud)
	return inf, nil
}

// hostsPublicos: las direcciones publicas que aparecen en las trazas.
func hostsPublicos(trazas []traza) []netip.Addr {
	visto := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, t := range trazas {
		for _, s := range t.Saltos {
			if clasificar(s.Host) != clasePublica {
				continue
			}
			a := netip.MustParseAddr(s.Host)
			if !visto[a] {
				visto[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func resumirASN(t tablaASN, hosts []netip.Addr, ipinfo, dbip string) resumenASN {
	r := resumenASN{ArchivoIPinfo: ipinfo, ArchivoDBIP: dbip, Nombres: map[int]string{}}
	for _, a := range hosts {
		i, ok := t[a]
		switch {
		case !ok:
			r.Desconocidas++
			continue
		case i.Fuente == "IPinfo":
			r.IPinfo++
		default:
			r.DBIP++
		}
		if _, ya := r.Nombres[i.ASN]; !ya || i.Fuente == "IPinfo" {
			r.Nombres[i.ASN] = i.Nombre
		}
	}
	return r
}

// ranuras: las corridas esperadas, una por cuarto de hora dentro de la ventana.
func ranuras(inicio, fin time.Time) []time.Time {
	var out []time.Time
	q := inicio.Truncate(periodoCorrida)
	if q.Before(inicio) {
		q = q.Add(periodoCorrida)
	}
	for ; q.Before(fin); q = q.Add(periodoCorrida) {
		out = append(out, q)
	}
	return out
}

// cubrir compara las trazas obtenidas con las esperadas: una por destino y
// corrida. Una traza pertenece a la corrida de su cuarto de hora (t truncado).
func cubrir(dest []destino, trazas []traza, inicio, fin time.Time) cobertura {
	c := cobertura{Inicio: inicio, Fin: fin, Trazas: len(trazas)}
	declarado := map[string]bool{}
	for _, d := range dest {
		declarado[d.IP] = true
	}
	ajenos := map[string]bool{}
	porRanura := map[time.Time]int{}
	for _, t := range trazas {
		if !declarado[t.Destino] {
			ajenos[t.Destino] = true
			continue
		}
		porRanura[t.T.Truncate(periodoCorrida)]++
	}
	rs := ranuras(inicio, fin)
	c.Ranuras = len(rs)
	for _, r := range rs {
		if n := porRanura[r]; n >= len(dest) {
			c.Completas++
		} else {
			c.Huecos = append(c.Huecos, hueco{r, n})
		}
	}
	for d := range ajenos {
		c.Ajenos = append(c.Ajenos, d)
	}
	sort.Strings(c.Ajenos)
	return c
}

// valida (12.1): mtr no nulo, y el ultimo salto es el destino con Loss% < 100.
func (t traza) valida() bool {
	n := len(t.Saltos)
	return n > 0 && t.Saltos[n-1].Host == t.Destino && t.Saltos[n-1].Loss < 100
}

// ladoCasa cuenta los saltos iniciales del lado de la casa (12.1): el prefijo
// mas largo de saltos privados, de CGNAT, de enlace local o del ASN de
// acceso. Un mudo dentro del prefijo no lo corta; los mudos del final no
// cuentan (de todos modos quedan fuera de la huella ASN).
func ladoCasa(s []salto, asn tablaASN, asnAcceso int) int {
	n := 0
	for i, x := range s {
		switch clasificar(x.Host) {
		case claseMudo:
		case clasePrivada, claseCGNAT, claseEnlaceLocal:
			n = i + 1
		case clasePublica:
			if asn.de(x.Host).ASN != asnAcceso {
				return n
			}
			n = i + 1
		default:
			return n
		}
	}
	return n
}

// huellaASN (12.1): el ASN de los saltos publicos despues del lado de la
// casa, sin mudos, con repetidos consecutivos colapsados. AS? es un ASN
// desconocido; tambien devuelve cuantos saltos lo tuvieron.
func huellaASN(s []salto, casa int, asn tablaASN) (string, int) {
	var toks []string
	desconocidos := 0
	for _, x := range s[casa:] {
		if clasificar(x.Host) != clasePublica {
			continue
		}
		tok := "AS?"
		if a := asn.de(x.Host).ASN; a != 0 {
			tok = "AS" + strconv.Itoa(a)
		} else {
			desconocidos++
		}
		if len(toks) == 0 || toks[len(toks)-1] != tok {
			toks = append(toks, tok)
		}
	}
	return strings.Join(toks, " "), desconocidos
}

// huellaIP (12.1): la secuencia de host de todos los saltos.
func huellaIP(s []salto) string {
	h := make([]string, len(s))
	for i, x := range s {
		h[i] = x.Host
	}
	return strings.Join(h, " ")
}

// percentil (12.1): rango mas cercano, la posicion ceil(p/100 * N) de la
// serie ordenada. Se calcula en enteros: en coma flotante 7/100*100 da
// 7.000000000000001 y ceil lo subiria una posicion.
func percentil(ordenada []float64, p int) (float64, bool) {
	n := len(ordenada)
	if n == 0 {
		return 0, false
	}
	k := max((p*n+99)/100, 1)
	return ordenada[k-1], true
}

// posibleArtefacto: una huella es la otra con ASN de menos, y la traza con
// menos ASN tiene mas saltos mudos: la firma de un router que no contesto,
// no de una ruta nueva. Solo marca; el cambio se cuenta igual.
func posibleArtefacto(de, a string, mudosDe, mudosA int) bool {
	x, y := strings.Fields(de), strings.Fields(a)
	mx, my := mudosDe, mudosA
	if len(x) > len(y) {
		x, y, mx, my = y, x, my, mx
	}
	return len(x) < len(y) && mx > my && subsecuencia(x, y)
}

func subsecuencia(x, y []string) bool {
	i := 0
	for _, t := range y {
		if i < len(x) && x[i] == t {
			i++
		}
	}
	return i == len(x)
}

// cambio de ruta ASN entre dos trazas validas consecutivas de un destino.
type cambio struct {
	Antes, Despues   time.Time // t_destino de las dos trazas que lo delimitan
	De, A            string    // huellas ASN
	PosibleArtefacto bool
	BGP              string // "si", "no" o "sin datos"; vacio si no se consulto
}

type estadDestino struct {
	destino
	Esperadas, Obtenidas, Validas int
	HayRTT                        bool
	P50, P95, BestMin, WrstMax    float64 // ms
	Cambios                       []cambio
	CambiosIP                     int
	RutaDominante                 string
	Prevalencia                   float64
	Mudos, Saltos                 int // en las trazas validas
	ConASDesconocido              int // trazas validas con algun AS?
	SaltosMax                     int
	Prefijo                       string // BGP
	Origen                        []int
	Anuncios, Retiros             int
	FinBGP                        time.Time
}

// estadisticas de un destino. "Consecutivas" = consecutivas entre las
// validas: una traza no valida en medio no cuenta como ruta.
func estadisticas(d destino, trs []traza, asn tablaASN, asnAcceso, esperadas int) estadDestino {
	e := estadDestino{destino: d, Esperadas: esperadas, Obtenidas: len(trs)}
	sort.Slice(trs, func(i, j int) bool { return trs[i].TDestino.Before(trs[j].TDestino) })
	var rtt []float64
	huellas := map[string]int{}
	var prev *traza
	var prevH, prevIP string
	var prevMudos int
	for i := range trs {
		t := &trs[i]
		if !t.valida() {
			continue
		}
		e.Validas++
		f := t.Saltos[len(t.Saltos)-1]
		rtt = append(rtt, f.Avg)
		if !e.HayRTT || f.Best < e.BestMin {
			e.BestMin = f.Best
		}
		e.HayRTT = true
		e.WrstMax = math.Max(e.WrstMax, f.Wrst)
		e.SaltosMax = max(e.SaltosMax, len(t.Saltos))
		m := 0
		for _, x := range t.Saltos {
			if x.Host == mudo {
				m++
			}
		}
		e.Mudos += m
		e.Saltos += len(t.Saltos)
		h, desc := huellaASN(t.Saltos, ladoCasa(t.Saltos, asn, asnAcceso), asn)
		if desc > 0 {
			e.ConASDesconocido++
		}
		hip := huellaIP(t.Saltos)
		huellas[h]++
		if prev != nil {
			if h != prevH {
				e.Cambios = append(e.Cambios, cambio{
					Antes: prev.TDestino, Despues: t.TDestino, De: prevH, A: h,
					PosibleArtefacto: posibleArtefacto(prevH, h, prevMudos, m),
				})
			}
			if hip != prevIP {
				e.CambiosIP++
			}
		}
		prev, prevH, prevIP, prevMudos = t, h, hip, m
	}
	sort.Float64s(rtt)
	e.P50, _ = percentil(rtt, 50)
	e.P95, _ = percentil(rtt, 95)
	mejor, nMejor := "", 0
	for h, n := range huellas {
		if n > nMejor || (n == nMejor && h < mejor) {
			mejor, nMejor = h, n
		}
	}
	if e.Validas > 0 {
		e.RutaDominante = mejor
		e.Prevalencia = float64(nMejor) / float64(e.Validas)
	}
	return e
}

type resumenSalud struct {
	Muestras, SinTemp          int
	TempMaxMC                  float64
	TempMaxT                   time.Time
	Episodios                  int
	ThrActivo, ThrNuevo, ThrNA int
	BitsNuevos                 uint64
	Subtension, SubtensionNA   int
	NTPMaxMs                   float64
	NTPMaxT                    time.Time
	NTPNA                      int
}

// resumirSalud (12.1): episodio caliente = 3 o mas muestras seguidas por
// encima del umbral (seguidas: a lo mas maxHuecoSalud entre una y otra);
// throttled nuevo = un bit de "ya ocurrio" que no estaba en la primera
// muestra legible de la ventana.
func resumirSalud(ms []muestraSalud) resumenSalud {
	r := resumenSalud{Muestras: len(ms)}
	var base uint64
	hayBase := false
	racha := 0
	for i, m := range ms {
		caliente := m.TempMC != nil && *m.TempMC > umbralCalienteMC
		seguida := i > 0 && m.T.Sub(ms[i-1].T) <= maxHuecoSalud
		switch {
		case !caliente:
			racha = 0
		case seguida:
			racha++
		default:
			racha = 1
		}
		if racha == muestrasCaliente {
			r.Episodios++
		}
		if m.TempMC == nil {
			r.SinTemp++
		} else if *m.TempMC > r.TempMaxMC {
			r.TempMaxMC, r.TempMaxT = *m.TempMC, m.T
		}
		if v, err := strconv.ParseUint(strings.TrimPrefix(m.Throttled, "0x"), 16, 64); err != nil {
			r.ThrNA++
		} else {
			if !hayBase {
				base, hayBase = v, true
			}
			if v&bitsThrottledActivo != 0 {
				r.ThrActivo++
			}
			if n := v & bitsThrottledOcurrio &^ base; n != 0 {
				r.ThrNuevo++
				r.BitsNuevos |= n
			}
		}
		switch {
		case m.Subtension == nil:
			r.SubtensionNA++
		case *m.Subtension != 0:
			r.Subtension++
		}
		if v, ok := ntpMs(m.NTP); !ok {
			r.NTPNA++
		} else if math.Abs(v) > math.Abs(r.NTPMaxMs) {
			r.NTPMaxMs, r.NTPMaxT = v, m.T
		}
	}
	return r
}

// timedatectl timesync-status escribe el desfase como "-583us", "-2.564ms" o "+1.2s".
var reNTP = regexp.MustCompile(`^([+-]?[0-9]+(?:\.[0-9]+)?)(us|µs|ms|s)$`)

func ntpMs(s string) (float64, bool) {
	m := reNTP.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	switch m[2] {
	case "us", "µs":
		v /= 1000
	case "s":
		v *= 1000
	}
	return v, true
}

type veredicto struct {
	Originales    int
	Faltan        []string // originales sin trazas validas: no se puede evaluar
	Cambios       int      // cambios ASN en los originales
	Artefactos    int      // de ellos, marcados como posible artefacto
	JitterMax     float64  // el mayor p95 - p50 de los originales, ms
	JitterDestino string
	Aborto        bool
	Enfriamiento  bool
	SaltosMax     int     // el camino mas largo, en todos los destinos
	WrstMax       float64 // el peor RTT de un destino, ms
}

func (v veredicto) evaluable() bool { return v.Originales > 0 && len(v.Faltan) == 0 }

// decidir aplica la tabla de 12.4. Es una propuesta: la firma el responsable.
func decidir(est []estadDestino, s resumenSalud) veredicto {
	var v veredicto
	for _, e := range est {
		v.SaltosMax = max(v.SaltosMax, e.SaltosMax)
		v.WrstMax = math.Max(v.WrstMax, e.WrstMax)
		if e.Grupo != grupoAborto {
			continue
		}
		v.Originales++
		if !e.HayRTT {
			v.Faltan = append(v.Faltan, e.IP)
			continue
		}
		v.Cambios += len(e.Cambios)
		for _, c := range e.Cambios {
			if c.PosibleArtefacto {
				v.Artefactos++
			}
		}
		if j := e.P95 - e.P50; v.JitterDestino == "" || j > v.JitterMax {
			v.JitterMax, v.JitterDestino = j, e.IP
		}
	}
	v.Aborto = v.evaluable() && v.Cambios == 0 && v.JitterMax < umbralJitterMs
	v.Enfriamiento = s.Episodios > 0 || s.ThrActivo > 0 || s.ThrNuevo > 0
	return v
}
