package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"codeberg.org/go-pdf/fpdf"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

func (s *Server) exportCapture(w http.ResponseWriter, r *http.Request) {
	format := r.PathValue("format")
	contentTypes := map[string]string{"csv": "text/csv; charset=utf-8", "jsonl": "application/x-ndjson", "pdf": "application/pdf"}
	if contentTypes[format] == "" {
		fail(w, http.StatusNotFound, "choose pdf, csv or jsonl")
		return
	}
	c, ok := s.requestedCapture(w, r)
	if !ok {
		return
	}
	var result bytes.Buffer
	var err error
	switch format {
	case "csv":
		err = exportCSV(&result, c)
	case "jsonl":
		err = exportJSONL(&result, c)
	case "pdf":
		err = exportPDF(&result, c)
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "could not generate the export")
		return
	}
	w.Header().Set("Content-Type", contentTypes[format])
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=tracertip-%s.%s", c.ID, format))
	result.WriteTo(w)
}

func exportJSONL(w io.Writer, c capture) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(struct {
		Type string `json:"type"`
		V    int    `json:"v"`
		captureInfo
	}{"capture", 1, c.captureInfo}); err != nil {
		return err
	}
	for _, round := range c.History.Rounds {
		if err := enc.Encode(round); err != nil {
			return err
		}
	}
	for _, e := range c.History.Events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

func exportCSV(w io.Writer, c capture) error {
	out := csv.NewWriter(w)
	out.UseCRLF = true
	if err := out.Write([]string{"record_type", "target", "time_utc", "first_observed_utc", "round", "ttl", "status", "address", "rtt_ms", "before_as", "after_as"}); err != nil {
		return err
	}
	for _, r := range c.History.Rounds {
		at := r.Start.UTC().Format(time.RFC3339Nano)
		for _, h := range r.Hops {
			if err := out.Write([]string{"hop", c.Target, at, "", strconv.Itoa(r.N), strconv.Itoa(h.TTL), h.Status, h.Addr, number(h.RTTms), "", ""}); err != nil {
				return err
			}
		}
	}
	for _, e := range c.History.Events {
		if err := out.Write([]string{"event", c.Target, e.Time.UTC().Format(time.RFC3339Nano), e.ObservedAt.UTC().Format(time.RFC3339Nano), strconv.Itoa(e.Round), strconv.Itoa(e.TTL), e.State, "", "", pathText(e.Before), pathText(e.After)}); err != nil {
			return err
		}
	}
	out.Flush()
	return out.Error()
}

func number(n *float64) string {
	if n == nil {
		return ""
	}
	return strconv.FormatFloat(*n, 'f', -1, 64)
}

func pathText(path []int) string {
	if len(path) == 0 {
		return "-"
	}
	items := make([]string, len(path))
	for i, asn := range path {
		items[i] = fmt.Sprintf("AS%d", asn)
	}
	return strings.Join(items, " > ")
}

func exportPDF(w io.Writer, c capture) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(18, 17, 18)
	pdf.SetAutoPageBreak(true, 16)
	pdf.SetTitle("tracertIP - Reporte de ruta", true)
	encode := pdf.UnicodeTranslatorFromDescriptor("cp1252")
	line := func(s string) { pdf.MultiCell(0, 5, encode(s), "", "L", false) }
	heading := func(s string) {
		pdf.Ln(4)
		pdf.SetFont("Helvetica", "B", 12)
		line(s)
		pdf.SetFont("Helvetica", "", 10)
	}
	utc := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(24, 55, 91)
	pdf.CellFormat(0, 12, "Reporte de ruta", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(25, 31, 38)
	line("tracertIP / " + c.ID)
	node := c.Node
	if node == "" {
		node = "Identidad no incluida"
	}
	line("Nodo de medición: " + node)
	line(fmt.Sprintf("Destino: %s", c.Target))
	line(fmt.Sprintf("Intervalo (UTC): %s a %s", utc(c.From), utc(c.To)))
	line(fmt.Sprintf("Guardado (UTC): %s", utc(c.SavedAt)))
	if c.Public {
		line("Vista pública")
	}
	if c.Note != "" {
		heading("Nota")
		line(strings.Map(func(r rune) rune {
			if r == '\n' || !unicode.IsControl(r) {
				return r
			}
			return ' '
		}, c.Note))
	}

	heading("Estado de las mediciones")
	var rtts []float64
	sent := 0
	for _, r := range c.History.Rounds {
		var best *float64
		measured := false
		for _, h := range r.Hops {
			measured = measured || h.Status != model.StatusSendError
			if h.Addr == c.Target && h.RTTms != nil && (best == nil || *h.RTTms < *best) {
				best = h.RTTms
			}
		}
		if measured {
			sent++
		}
		if best != nil {
			rtts = append(rtts, *best)
		}
	}
	line(fmt.Sprintf("Rondas registradas: %d  |  Con envío: %d  |  Con respuesta del destino: %d", c.Rounds, sent, len(rtts)))
	if len(rtts) > 0 {
		slices.Sort(rtts)
		line(fmt.Sprintf("RTT mínimo: %.2f ms  |  Mediana: %.2f ms", rtts[0], rtts[(len(rtts)-1)/2]))
		if len(rtts) >= 59 {
			line(fmt.Sprintf("RTT p95: %.2f ms", rtts[(95*len(rtts)+99)/100-1]))
		}
	}
	if c.Rounds > 0 {
		heading("Saltos de la última ronda")
		r := c.History.Rounds[len(c.History.Rounds)-1]
		line(utc(r.Start) + " UTC")
		for _, h := range r.Hops {
			addr := h.Addr
			switch {
			case addr != "" && h.RTTms != nil:
				addr += fmt.Sprintf("  |  %.2f ms", *h.RTTms)
			case h.RTTms != nil:
				addr = fmt.Sprintf("Dirección oculta  |  %.2f ms", *h.RTTms)
			case h.Status == model.StatusSendError:
				addr = "Sonda no enviada"
			default:
				addr = "Sin respuesta"
			}
			line(fmt.Sprintf("TTL %d  |  %s", h.TTL, addr))
		}
	}
	heading("Cambios de ruta")
	if c.Events == 0 {
		line("Sin cambios registrados en el intervalo.")
	}
	for _, event := range c.History.Events {
		pdf.Ln(2)
		line(fmt.Sprintf("%s UTC  |  TTL %d  |  %s", utc(event.Time), event.TTL, event.State))
		if !event.ObservedAt.IsZero() && !event.ObservedAt.Equal(event.Time) {
			line("Primera observación: " + utc(event.ObservedAt) + " UTC")
		}
		line("Antes: " + pathText(event.Before))
		line("Después: " + pathText(event.After))
	}
	return pdf.Output(w)
}
