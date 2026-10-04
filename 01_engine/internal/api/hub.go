// Package api serves the live telemetry on the LAN: read-only JSON under
// /v1 and a Server-Sent Events stream (00_IDEA 5), with the home side hidden
// on request by the server itself (5.ter).
package api

import "sync"

// MaxStreams bounds the live connections: each holds a goroutine and a
// buffer, and the node has no need for more viewers than a household
// (OWASP API Top 10 2023, API4: unrestricted resource consumption).
const MaxStreams = 8

// streamBuffer is how many messages a viewer may fall behind before it is
// dropped: 30 s of rounds from five targets. A stalled viewer never slows
// the others or the probing.
const streamBuffer = 75

// Hub fans messages out to the live streams. Each message comes in two
// forms, full and public; a viewer gets the one it asked for.
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]bool // value: the viewer wants the public form
}

// NewHub has no viewers yet.
func NewHub() *Hub { return &Hub{subs: map[chan []byte]bool{}} }

// Subscribe adds a viewer; ok is false when MaxStreams are already open.
// The channel closes if the viewer falls behind or cancel is called.
func (h *Hub) Subscribe(public bool) (ch <-chan []byte, cancel func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= MaxStreams {
		return nil, nil, false
	}
	c := make(chan []byte, streamBuffer)
	h.subs[c] = public
	return c, func() { h.drop(c) }, true
}

func (h *Hub) drop(c chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[c]; ok {
		delete(h.subs, c)
		close(c)
	}
}

// Publish sends each viewer its form of the message without blocking.
func (h *Hub) Publish(full, public []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c, pub := range h.subs {
		msg := full
		if pub {
			msg = public
		}
		select {
		case c <- msg:
		default:
			delete(h.subs, c)
			close(c)
		}
	}
}
