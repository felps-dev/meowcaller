package meowcaller

// TEMPORARY DIAGNOSTIC — remove once purpshell/meowcaller#40 is understood.
//
// # The one question this file exists to answer
//
// On the integrator's deployment, inbound audio stops after ~180 ms on every
// answered call: eight calls, three different relays, two to four decoded
// frames each. The relay CHOICE is refuted as the cause — the constancy
// across relays says the media path establishes and then dies a few packets
// in. Two explanations remain, and they live in different halves of the
// stack:
//
//   - datagrams keep ARRIVING and stop decrypting → SRTP state (ROC
//     estimation, a rekey, the WARP MI tag, a key epoch).
//   - datagrams stop ARRIVING → the relay bridge, or the STUN
//     consent/keepalive path.
//
// Nothing in the existing instrumentation separates those. relayRx counts
// datagrams but is read once, at 400 ms and 900 ms, to decide whether the
// allocate was delivered; the per-packet diag categories carry the detail but
// are a maintainer carve-out that must never run in production, and the
// first-of-each-kind log lines deliberately fire ONCE, which is exactly the
// wrong shape for "it worked three times and then stopped".
//
// So this file counts the receive path at every stage it can fail, and emits
// the counts periodically WHILE the call is live as well as once at teardown.
// Periodically matters: a stall at 180 ms of a 10 s call is visible in a 5 s
// snapshot as two intervals that disagree, where a single post-mortem total
// cannot distinguish "stopped arriving at 180 ms" from "arrived all along".
//
// # What it may carry, and why that is a hard line
//
// It runs in production, on a live WhatsApp credential, through the
// integrator's ordinary structured log. So: counters, RTP sequence numbers,
// ROC values, SSRCs and failure-KIND names. No key material, no call key, no
// payload bytes, no PCM, no RMS, not one byte of anything a peer said. The
// test for this file asserts that over the EMITTED form rather than field by
// field, because a field added later is exactly the leak a field-by-field
// assertion does not see.

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// mediaCensusInterval is how often a LIVE call publishes a snapshot.
//
// CHOSEN, at roughly a third of the shortest call this bug has been seen on,
// so that a call which carries three frames and then stops produces at least
// two disagreeing snapshots. It is not a pacing value and nothing waits on
// it: a snapshot is a map copy and six words.
const mediaCensusInterval = 5 * time.Second

// Why a packet the audio path refused was refused. One constant per `return
// ..., false` on the path from a classified RTP datagram to PCM, so a count
// names a line of code rather than a layer.
//
// There is deliberately NO replay constant. This stack has no replay window:
// nothing on the receive path rejects a sequence number it has already
// accepted, so a "replay" counter here could only ever read zero and would
// retire the hypothesis without ever having tested it. The nearest honest
// observable is SeqRegressions, below, which counts a decrypted packet whose
// sequence number did not advance — and which is evidence FOR looking at the
// ROC estimator, since that is the input EstimateRoc branches on.
const (
	// CensusFailNoContext: the datagram parsed as RTP and carried an audio
	// payload type, but its SSRC matches no active participant receiver. On a
	// one-to-one call this is the signature of a key epoch or roster change
	// the receive registry did not follow — the packet is fine and we have
	// nowhere to take it.
	CensusFailNoContext = "no_context"

	// CensusFailUnparsableRTP: classified as RTP by the relay layer and then
	// failed to parse as an RTP header.
	CensusFailUnparsableRTP = "unparsable_rtp"

	// CensusFailTooShort: shorter than an RTP header plus the WARP MI tag.
	CensusFailTooShort = "too_short"

	// CensusFailMalformedHeader: the header did not parse once the MI tag was
	// stripped, or its declared length left no payload.
	CensusFailMalformedHeader = "malformed_header"

	// CensusFailAuthTag: the WARP MI tag did not verify against the receive
	// auth key at the estimated ROC. THE kind to watch. A call that decodes
	// three frames and then counts these is the SRTP-state answer, and the
	// ROC in the report says whether the estimator moved.
	CensusFailAuthTag = "auth_tag"

	// CensusFailDecrypt: the tag verified and AES-CM then failed.
	CensusFailDecrypt = "decrypt"

	// CensusFailDecodeEmpty: unprotected, and the codec returned no samples.
	// Not a crypto fault — it is the one failure mode that would put the bug
	// in mlow rather than in SRTP or the transport.
	CensusFailDecodeEmpty = "decode_empty"
)

// censusFailKinds is every kind, in the order a packet could meet them. The
// snapshot renders them in this order so two snapshots of one call line up
// column for column.
var censusFailKinds = []string{
	CensusFailNoContext, CensusFailUnparsableRTP, CensusFailTooShort,
	CensusFailMalformedHeader, CensusFailAuthTag, CensusFailDecrypt,
	CensusFailDecodeEmpty,
}

// CensusPacket is the sequence/ROC pair of one successfully decrypted packet.
// First and last of these are what say whether the inbound stream stopped
// mid-flight and where.
type CensusPacket struct {
	Seq  uint16 `json:"seq"`
	ROC  uint32 `json:"roc"`
	SSRC uint32 `json:"ssrc"`
}

func (p CensusPacket) String() string {
	return fmt.Sprintf("seq=%d roc=%d ssrc=%d", p.Seq, p.ROC, p.SSRC)
}

// MediaCensus is one snapshot of a call's inbound receive path.
//
// It is a VALUE: the observer gets a copy and the collector keeps counting.
// Every field is cumulative since the call's media started, including on the
// periodic emissions — a reader subtracts two snapshots to get an interval,
// and a counter that reset itself per interval could not answer "how many in
// total", which is the question a teardown emission is for.
type MediaCensus struct {
	CallID string `json:"call_id"`

	// Inbound is the direction of the CALL (true = we are the callee), carried
	// so a census line can be read without its matching endpoint-selection
	// line.
	Inbound bool `json:"inbound"`

	// Final distinguishes the teardown emission from a periodic one.
	Final bool `json:"final"`

	// ElapsedMS is milliseconds since the media loop started. It is what makes
	// two snapshots a RATE, and what puts the ~180 ms stall on a clock.
	ElapsedMS int64 `json:"elapsed_ms"`

	// Datagrams is every datagram read off the media socket, before any
	// classification — the number whose STOPPING is one of the two answers.
	Datagrams uint64 `json:"datagrams"`

	// Bytes is their total size. Carried because a relay that keeps the
	// bridge alive with keepalives alone shows as datagrams still arriving at
	// a collapsed byte rate, which neither counter says on its own.
	Bytes uint64 `json:"bytes"`

	// The classification breakdown. These sum to Datagrams.
	RTP          uint64 `json:"rtp"`
	RTCP         uint64 `json:"rtcp"`
	STUN         uint64 `json:"stun"`
	Other        uint64 `json:"other"`
	GroupInvalid uint64 `json:"group_invalid"`

	// The RTP payload breakdown. Audio + Video + AppData + UnknownPayload +
	// (RTP packets that failed to parse) sum to RTP.
	Audio          uint64 `json:"audio"`
	Video          uint64 `json:"video"`
	AppData        uint64 `json:"app_data"`
	UnknownPayload uint64 `json:"unknown_payload"`

	// UnprotectAttempts is audio RTP packets handed to the receive registry —
	// Successes + the sum of Failures.
	UnprotectAttempts uint64 `json:"unprotect_attempts"`

	// UnprotectSuccesses is packets that authenticated AND decrypted. It
	// counts the CRYPTO succeeding, which is not the same as audio arriving:
	// an empty codec output still counts here and not in FramesDecoded.
	UnprotectSuccesses uint64 `json:"unprotect_successes"`

	// Failures is keyed by the CensusFail* constants. A kind that never
	// happened is absent rather than zero, so a snapshot reads as the list of
	// things that actually went wrong.
	Failures map[string]uint64 `json:"failures,omitempty"`

	// FramesDecoded is packets that came out of the codec with samples: the
	// number the integrator's own frames_in should agree with, and a
	// disagreement is a bug above this seam rather than below it.
	FramesDecoded uint64 `json:"frames_decoded"`

	// SeqRegressions counts a decrypted packet whose sequence number did not
	// advance on the previous one. See the note on the absent replay kind.
	SeqRegressions uint64 `json:"seq_regressions"`

	// First and Last decrypted packet. Nil before anything decrypted, which
	// is itself the meowcaller#40 signature when Datagrams is large.
	First *CensusPacket `json:"first,omitempty"`
	Last  *CensusPacket `json:"last,omitempty"`

	// RTCPAuthFailures is peer SRTCP that failed authentication. It belongs
	// here because SRTCP is keyed from the SAME call key by a sibling
	// derivation: control authenticating while media does not narrows the
	// fault to the media key schedule, and both failing points at the call
	// key itself.
	RTCPAuthFailures uint64 `json:"rtcp_auth_failures"`

	// STUNBindingsAnswered is binding requests we answered. A relay that
	// stops bridging while still asking is the consent-path answer.
	STUNBindingsAnswered uint64 `json:"stun_bindings_answered"`
}

// Summary is the one-line human form. It is the line an operator greps and it
// is safe to print anywhere, by the same rule as the struct: counters, seqs
// and ROCs only.
func (c MediaCensus) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "elapsed_ms=%d final=%t datagrams=%d bytes=%d rtp=%d rtcp=%d stun=%d other=%d",
		c.ElapsedMS, c.Final, c.Datagrams, c.Bytes, c.RTP, c.RTCP, c.STUN, c.Other)
	fmt.Fprintf(&b, " audio=%d video=%d app_data=%d unknown_pt=%d",
		c.Audio, c.Video, c.AppData, c.UnknownPayload)
	fmt.Fprintf(&b, " unprotect=%d/%d frames=%d seq_regressions=%d",
		c.UnprotectSuccesses, c.UnprotectAttempts, c.FramesDecoded, c.SeqRegressions)
	first, last := "none", "none"
	if c.First != nil {
		first = c.First.String()
	}
	if c.Last != nil {
		last = c.Last.String()
	}
	fmt.Fprintf(&b, " first=[%s] last=[%s]", first, last)
	fails := make([]string, 0, len(c.Failures))
	for _, kind := range censusFailKinds {
		if n := c.Failures[kind]; n > 0 {
			fails = append(fails, fmt.Sprintf("%s=%d", kind, n))
		}
	}
	if len(fails) > 0 {
		fmt.Fprintf(&b, " failures=[%s]", strings.Join(fails, " "))
	}
	return b.String()
}

// mediaCensus is the collector. One per call's media loop.
//
// A plain mutex and not atomics: every counting site but one is on the single
// receive goroutine, the snapshot is taken from the periodic goroutine, and a
// struct of fifteen atomics would make the First/Last pair — which must move
// together with the sequence check — impossible to keep consistent anyway.
type mediaCensus struct {
	mu   sync.Mutex
	snap MediaCensus
	// lastSeq tracks the previous decrypted sequence number, for
	// SeqRegressions. Held separately from snap.Last because Last is handed
	// out and a regression must be judged against what we saw, not against
	// what we reported.
	lastSeq  uint16
	haveLast bool
	failures map[string]uint64
}

func newMediaCensus(callID string, inbound bool) *mediaCensus {
	return &mediaCensus{
		snap:     MediaCensus{CallID: callID, Inbound: inbound},
		failures: map[string]uint64{},
	}
}

// datagram counts one read off the media socket, before classification.
func (c *mediaCensus) datagram(bytes int) {
	c.mu.Lock()
	c.snap.Datagrams++
	c.snap.Bytes += uint64(bytes)
	c.mu.Unlock()
}

// classified counts one datagram's relay-layer class.
func (c *mediaCensus) classified(kind string) {
	c.mu.Lock()
	switch kind {
	case censusClassRTP:
		c.snap.RTP++
	case censusClassRTCP:
		c.snap.RTCP++
	case censusClassSTUN:
		c.snap.STUN++
	case censusClassGroupInvalid:
		c.snap.GroupInvalid++
	default:
		c.snap.Other++
	}
	c.mu.Unlock()
}

// The relay-layer classes, as this file names them. Separate constants from
// relay.RelayPacket* so the census's own vocabulary is stable under a change
// to that enum, and so the group-forwarding refusal — which happens BEFORE
// classification — has a name at all.
const (
	censusClassRTP          = "rtp"
	censusClassRTCP         = "rtcp"
	censusClassSTUN         = "stun"
	censusClassOther        = "other"
	censusClassGroupInvalid = "group_invalid"
)

// payload counts one parsed RTP packet's payload class.
func (c *mediaCensus) payload(kind mediaPayloadKind) {
	c.mu.Lock()
	switch kind {
	case mediaPayloadAudio:
		c.snap.Audio++
	case mediaPayloadVideo:
		c.snap.Video++
	case mediaPayloadAppData:
		c.snap.AppData++
	default:
		c.snap.UnknownPayload++
	}
	c.mu.Unlock()
}

// rtpUnparsable counts a datagram the relay classified as RTP whose header
// did not parse. Deliberately NOT an unprotect attempt: it never reached the
// audio receive registry, and folding it into the attempts would make the
// attempts/successes ratio disagree with the audio count for a reason that
// has nothing to do with crypto.
func (c *mediaCensus) rtpUnparsable() {
	c.mu.Lock()
	c.failures[CensusFailUnparsableRTP]++
	c.mu.Unlock()
}

// unprotectFailed counts one audio packet the receive path refused, by kind.
func (c *mediaCensus) unprotectFailed(kind string) {
	c.mu.Lock()
	c.snap.UnprotectAttempts++
	c.failures[kind]++
	c.mu.Unlock()
}

// decrypted counts one audio packet that authenticated and decrypted, and
// records its position in the stream. samples is how many PCM samples the
// codec then produced; zero is counted as the decode_empty failure kind even
// though the crypto succeeded, because the integrator's question is about
// AUDIO and a frame with no samples is not audio.
func (c *mediaCensus) decrypted(p CensusPacket, samples int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snap.UnprotectAttempts++
	c.snap.UnprotectSuccesses++
	if c.haveLast && p.Seq <= c.lastSeq {
		c.snap.SeqRegressions++
	}
	c.lastSeq, c.haveLast = p.Seq, true
	if c.snap.First == nil {
		first := p
		c.snap.First = &first
	}
	last := p
	c.snap.Last = &last
	if samples > 0 {
		c.snap.FramesDecoded++
	} else {
		c.failures[CensusFailDecodeEmpty]++
	}
}

func (c *mediaCensus) rtcpAuthFailed() {
	c.mu.Lock()
	c.snap.RTCPAuthFailures++
	c.mu.Unlock()
}

func (c *mediaCensus) stunBindingAnswered() {
	c.mu.Lock()
	c.snap.STUNBindingsAnswered++
	c.mu.Unlock()
}

// snapshot copies the counters. elapsedMS and final are the caller's, because
// the collector does not own a clock and does not know which emission is the
// last one.
func (c *mediaCensus) snapshot(elapsedMS int64, final bool) MediaCensus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.snap
	out.ElapsedMS = elapsedMS
	out.Final = final
	// Deep-copy the three reference fields. Without this the observer holds
	// the collector's own map and pointers and reads them, unsynchronised,
	// while the receive goroutine keeps writing — a data race that would
	// corrupt the one measurement this file exists to take.
	if len(c.failures) > 0 {
		out.Failures = make(map[string]uint64, len(c.failures))
		for k, v := range c.failures {
			out.Failures[k] = v
		}
	}
	if c.snap.First != nil {
		first := *c.snap.First
		out.First = &first
	}
	if c.snap.Last != nil {
		last := *c.snap.Last
		out.Last = &last
	}
	return out
}

// report emits one snapshot through the library's logger, the diag recorder
// and the integrator's observer.
func (e *engine) reportMediaCensus(c MediaCensus) {
	e.c.log.Info().
		Str("call_id", c.CallID).
		Bool("inbound", c.Inbound).
		Bool("final", c.Final).
		Int64("elapsed_ms", c.ElapsedMS).
		Uint64("datagrams", c.Datagrams).
		Uint64("rtp", c.RTP).
		Uint64("audio", c.Audio).
		Uint64("unprotect_successes", c.UnprotectSuccesses).
		Uint64("frames_decoded", c.FramesDecoded).
		Interface("failures", c.Failures).
		Interface("first", c.First).
		Interface("last", c.Last).
		Msg("media census (temporary diagnostic, upstream issue #40)")
	e.c.diag.Emit("relay", map[string]any{
		"event": "media_census", "call_id": c.CallID, "final": c.Final,
		"elapsed_ms": c.ElapsedMS, "datagrams": c.Datagrams, "rtp": c.RTP,
		"audio": c.Audio, "unprotect_successes": c.UnprotectSuccesses,
		"frames_decoded": c.FramesDecoded, "failures": c.Failures,
	})
	if fn := e.c.mediaCensusObserver; fn != nil {
		fn(c)
	}
}
