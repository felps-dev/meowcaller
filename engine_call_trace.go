package meowcaller

// TEMPORARY DIAGNOSTIC — remove with the media census once inbound audio is
// confirmed working (upstream #40; fix under test: ports of #26 and #43).
//
// Two questions the ports cannot answer about OUR calls on their own:
//
//  1. Does the caller probe relays outside our offer? #26's explanation of the
//     silence is that our relaylatency echo endorsed the caller's nearest edge
//     outside the offer. The probed relay names beside the offer's, and which
//     were skipped, confirm or kill that on our own traffic.
//  2. How long is our offer -> media -> answer path? #43's evidence is that a
//     late allocate gets no inbound media. The timeline puts our own delays on
//     a clock, relative to the offer's arrival.
//
// Both ride on the media census (MediaCensus.Trace), so one call's story stays
// on the census lines. Relay names and millisecond offsets only: no key, no
// token, no address bytes.

import (
	"sync"
	"time"
)

// CensusTimeline is one inbound call's milestones, in milliseconds since its
// offer arrived. A nil field has not happened (yet).
type CensusTimeline struct {
	// CallKeyMS: the offer's call key decrypted.
	CallKeyMS *int64 `json:"callkey_ms,omitempty"`
	// MediaStartMS: the media loop started (early, at the offer, unless the
	// call declined early media).
	MediaStartMS *int64 `json:"media_start_ms,omitempty"`
	// MuteV2MS: the caller's first mute_v2 arrived.
	MuteV2MS *int64 `json:"mute_v2_ms,omitempty"`
	// AnswerMS: Answer was called.
	AnswerMS *int64 `json:"answer_ms,omitempty"`
	// AcceptSentMS: the deferred <accept> left. Before #43 it followed the
	// first mute_v2 after Answer; with a mute_v2 held from ringing it leaves
	// from Answer itself.
	AcceptSentMS *int64 `json:"accept_sent_ms,omitempty"`
	// FirstRTPMS: the first inbound RTP decoded.
	FirstRTPMS *int64 `json:"first_rtp_ms,omitempty"`
}

// CensusTrace is the per-call part of the census that is not a receive-path
// counter: the relay election and the timeline.
type CensusTrace struct {
	// OfferRelays is the relay names of the offer's <te2> endpoints.
	OfferRelays []string `json:"offer_relays,omitempty"`
	// ProbedRelays counts the caller's relaylatency probes by relay name;
	// SkippedRelays the ones not answered because the relay is outside the
	// offer. A name in SkippedRelays is the out-of-offer edge #26 describes.
	ProbedRelays  map[string]uint64 `json:"probed_relays,omitempty"`
	SkippedRelays map[string]uint64 `json:"skipped_relays,omitempty"`
	Timeline      CensusTimeline    `json:"timeline"`
}

// callTrace collects a CensusTrace for one call. Methods are nil-safe: an
// outbound call has none.
type callTrace struct {
	offer time.Time

	mu    sync.Mutex
	trace CensusTrace
}

func newCallTrace(offer time.Time) *callTrace {
	return &callTrace{offer: offer}
}

type traceMilestone int

const (
	traceCallKey traceMilestone = iota
	traceMediaStart
	traceMuteV2
	traceAnswer
	traceAcceptSent
	traceFirstRTP
)

// mark records a milestone the first time it happens; later calls keep the
// first.
func (t *callTrace) mark(m traceMilestone) {
	if t == nil {
		return
	}
	ms := time.Since(t.offer).Milliseconds()
	t.mu.Lock()
	defer t.mu.Unlock()
	var slot **int64
	switch m {
	case traceCallKey:
		slot = &t.trace.Timeline.CallKeyMS
	case traceMediaStart:
		slot = &t.trace.Timeline.MediaStartMS
	case traceMuteV2:
		slot = &t.trace.Timeline.MuteV2MS
	case traceAnswer:
		slot = &t.trace.Timeline.AnswerMS
	case traceAcceptSent:
		slot = &t.trace.Timeline.AcceptSentMS
	case traceFirstRTP:
		slot = &t.trace.Timeline.FirstRTPMS
	default:
		return
	}
	if *slot == nil {
		*slot = &ms
	}
}

// offerRelays records the offer's relay names, once.
func (t *callTrace) offerRelays(rd *relayData) {
	if t == nil || rd == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.trace.OfferRelays != nil {
		return
	}
	names := make([]string, 0, len(rd.endpoints))
	for i := range rd.endpoints {
		names = append(names, rd.endpoints[i].relayName)
	}
	t.trace.OfferRelays = names
}

// probes records one relaylatency stanza: every relay name probed and the
// ones skipped as outside the offer.
func (t *callTrace) probes(probed, skipped []string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, name := range probed {
		if t.trace.ProbedRelays == nil {
			t.trace.ProbedRelays = map[string]uint64{}
		}
		t.trace.ProbedRelays[name]++
	}
	for _, name := range skipped {
		if t.trace.SkippedRelays == nil {
			t.trace.SkippedRelays = map[string]uint64{}
		}
		t.trace.SkippedRelays[name]++
	}
}

// snapshot deep-copies the trace for a census emission.
func (t *callTrace) snapshot() *CensusTrace {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := CensusTrace{
		OfferRelays:   append([]string(nil), t.trace.OfferRelays...),
		ProbedRelays:  copyCensusCounters(t.trace.ProbedRelays),
		SkippedRelays: copyCensusCounters(t.trace.SkippedRelays),
	}
	tl := t.trace.Timeline
	for _, p := range []**int64{&tl.CallKeyMS, &tl.MediaStartMS, &tl.MuteV2MS, &tl.AnswerMS, &tl.AcceptSentMS, &tl.FirstRTPMS} {
		if *p != nil {
			v := **p
			*p = &v
		}
	}
	out.Timeline = tl
	return &out
}
