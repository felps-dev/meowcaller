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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/purpshell/meowcaller/stun"
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

// The STUN message classes this census distinguishes, one per answer the
// relay can give us. Patch 5 exists because none of them was ever told apart:
// the receive loop tested only for MsgBindingRequest and let every other STUN
// type fall through to `continue`, so an allocate ERROR and an allocate
// SUCCESS produced exactly the same observable — none.
//
// The classifier is built out of the fork's four already-present response
// parsers (IsAllocateError, IsWhatsappPong, IsAllocateOrBindingSuccess,
// ParseStunErrorCode), which had no non-test caller at all. A fifth parser
// written beside them could disagree with the behaviour it describes; these
// cannot.
const (
	// CensusStunAllocateSuccess: the relay accepted an allocate. The INITIAL
	// one succeeding and the 1 Hz refreshes then not is the live hypothesis.
	CensusStunAllocateSuccess = "allocate_success"

	// CensusStunAllocateError: the relay REFUSED an allocate. THE kind to
	// watch, and the one with an error code beside it.
	CensusStunAllocateError = "allocate_error"

	// CensusStunBindingSuccess is kept apart from allocate_success even
	// though IsAllocateOrBindingSuccess conflates them: a binding success is
	// the relay acking a binding exchange and says nothing about whether our
	// allocation still exists. Folding the two would let a healthy ack read
	// as an accepted allocate, which is the one mistake this classifier must
	// not make.
	CensusStunBindingSuccess = "binding_success"

	// CensusStunBindingRequest: the relay asking US for consent freshness.
	// Already answered (SendBindingSuccess) and already counted
	// (STUNBindingsAnswered); counted here too so the type breakdown sums.
	CensusStunBindingRequest = "binding_request"

	// CensusStunPong: the answer to our 1 Hz consent ping. Arriving at ~1/s
	// with nothing else is a socket kept alive around a dead bridge.
	CensusStunPong = "pong"

	// CensusStunOther: a STUN type none of the above matched. Its raw 16-bit
	// message type is reported in STUNOtherTypes, so an unexpected type names
	// itself instead of hiding in a catch-all.
	CensusStunOther = "other"
)

// censusStunKinds is every STUN class, in the order a reader wants them: the
// allocate answers first, because they are the question.
var censusStunKinds = []string{
	CensusStunAllocateSuccess, CensusStunAllocateError,
	CensusStunBindingSuccess, CensusStunBindingRequest,
	CensusStunPong, CensusStunOther,
}

// CensusAllocateError is the FIRST allocate refusal of a call.
//
// The elapsed time is the field that carries the diagnosis: a refusal at
// ~1000 ms says the first 1 Hz refresh was rejected while the initial
// allocate was accepted, which is exactly the shape of "five packets bridged
// and then nothing for the next three minutes". A refusal at 0 ms would say
// something quite different — that the bridge never formed at all.
type CensusAllocateError struct {
	// Code is the STUN error code (class*100+number), 0 when the response
	// carried no ERROR-CODE attribute. CodeFound says which of the two it is,
	// because 0 is not a code and must not read as one.
	Code      uint16 `json:"code"`
	CodeFound bool   `json:"code_found"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

func (e CensusAllocateError) String() string {
	code := "absent"
	if e.CodeFound {
		code = strconv.FormatUint(uint64(e.Code), 10)
	}
	return fmt.Sprintf("code=%s at=%dms", code, e.ElapsedMS)
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

	// STUNTypes is the inbound STUN breakdown, keyed by the CensusStun*
	// classes. It sums to STUN. Absent rather than empty, like Failures.
	STUNTypes map[string]uint64 `json:"stun_types,omitempty"`

	// STUNOtherTypes is the raw 16-bit message type, hex, of every datagram
	// that landed in CensusStunOther, so a type we did not anticipate names
	// itself rather than disappearing into a catch-all.
	STUNOtherTypes map[string]uint64 `json:"stun_other_types,omitempty"`

	// AllocateErrors counts allocate refusals BY STUN ERROR CODE, keyed by
	// the decimal code ("437") or "none" for a refusal that carried no
	// ERROR-CODE attribute. The code is what aims the fix: this change only
	// measures.
	AllocateErrors map[string]uint64 `json:"allocate_errors,omitempty"`

	// FirstAllocateError is the first refusal and WHEN it arrived. Nil means
	// no allocate was ever refused, which is itself a reading.
	FirstAllocateError *CensusAllocateError `json:"first_allocate_error,omitempty"`

	// The allocate transaction ids, hex. SendCurrent replays the INITIAL
	// allocate packet — transaction id included — once a second, and a relay
	// may read a repeated transaction id as a retransmission or as a
	// conflicting re-allocation. Nothing here CHANGES that; the two ids are
	// reported side by side so a reader can see at a glance whether they are
	// the same.
	AllocateTxInitial string `json:"allocate_tx_initial,omitempty"`
	AllocateTxRefresh string `json:"allocate_tx_refresh,omitempty"`

	// AllocateRefreshes is refreshes sent; AllocateRefreshTxReused is how
	// many of them carried the initial transaction id. Zero refreshes with a
	// live call would be its own finding, so both are published even at zero.
	AllocateRefreshes       uint64 `json:"allocate_refreshes"`
	AllocateRefreshTxReused uint64 `json:"allocate_refresh_tx_reused"`

	// Relays is the inbound traffic per bound relay, keyed by relay name: the
	// fan-out (upstream PR #26) binds every offered relay, and this says which
	// one the caller's media actually came through — and whether it moved.
	Relays map[string]CensusRelay `json:"relays,omitempty"`

	// Duplicates is RTP dropped because the same (SSRC, seq) already arrived
	// through another relay. Non-zero means two relays bridged the caller.
	Duplicates uint64 `json:"duplicates"`

	// Trace is the relay election and the offer->media->answer timeline, for
	// an inbound call (engine_call_trace.go).
	Trace *CensusTrace `json:"trace,omitempty"`
}

// CensusRelay is one bound relay's inbound share.
type CensusRelay struct {
	Datagrams  uint64 `json:"datagrams"`
	RTP        uint64 `json:"rtp"`
	Duplicates uint64 `json:"duplicates"`
}

// RefreshReusesInitialTransactionID is the at-a-glance form of the two ids: a
// refresh has been sent and it carried the initial transaction id.
func (c MediaCensus) RefreshReusesInitialTransactionID() bool {
	return c.AllocateRefreshTxReused > 0
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
	if types := renderCensusCounters(c.STUNTypes, censusStunKinds); types != "" {
		fmt.Fprintf(&b, " stun_types=[%s]", types)
	}
	if other := renderCensusCounters(c.STUNOtherTypes, nil); other != "" {
		fmt.Fprintf(&b, " stun_other_types=[%s]", other)
	}
	if errs := renderCensusCounters(c.AllocateErrors, nil); errs != "" {
		fmt.Fprintf(&b, " allocate_errors=[%s]", errs)
	}
	if c.FirstAllocateError != nil {
		fmt.Fprintf(&b, " first_allocate_error=[%s]", c.FirstAllocateError.String())
	}
	fmt.Fprintf(&b, " allocate_refreshes=%d tx_initial=%s tx_refresh=%s tx_reused=%t",
		c.AllocateRefreshes, censusTxOrNone(c.AllocateTxInitial),
		censusTxOrNone(c.AllocateTxRefresh), c.RefreshReusesInitialTransactionID())
	if len(c.Relays) > 0 {
		names := make([]string, 0, len(c.Relays))
		for name := range c.Relays {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			r := c.Relays[name]
			parts = append(parts, fmt.Sprintf("%s:%d/%d/%d", name, r.Datagrams, r.RTP, r.Duplicates))
		}
		fmt.Fprintf(&b, " relays(dgram/rtp/dup)=[%s] duplicates=%d", strings.Join(parts, " "), c.Duplicates)
	}
	if c.Trace != nil {
		fmt.Fprintf(&b, " offer_relays=[%s] probed=[%s] skipped=[%s] timeline=[%s]",
			strings.Join(c.Trace.OfferRelays, " "),
			renderCensusCounters(c.Trace.ProbedRelays, nil),
			renderCensusCounters(c.Trace.SkippedRelays, nil),
			c.Trace.Timeline.String())
	}
	return b.String()
}

// String renders the timeline as "callkey=12 media_start=14 ..." in event
// order, omitting what has not happened.
func (t CensusTimeline) String() string {
	var parts []string
	for _, f := range []struct {
		name string
		v    *int64
	}{
		{"callkey", t.CallKeyMS}, {"media_start", t.MediaStartMS}, {"mute_v2", t.MuteV2MS},
		{"answer", t.AnswerMS}, {"accept_sent", t.AcceptSentMS}, {"first_rtp", t.FirstRTPMS},
	} {
		if f.v != nil {
			parts = append(parts, fmt.Sprintf("%s=%d", f.name, *f.v))
		}
	}
	return strings.Join(parts, " ")
}

// censusTxOrNone renders a transaction id, or "none" for one we never saw —
// an empty string in a greppable line reads as a parsing accident.
func censusTxOrNone(txHex string) string {
	if txHex == "" {
		return "none"
	}
	return txHex
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
	// The three STUN-side maps, held beside failures and for the same
	// reason: they are handed out by value on every snapshot and the receive
	// goroutine keeps writing to these.
	stunTypes      map[string]uint64
	stunOtherTypes map[string]uint64
	allocateErrors map[string]uint64

	// Per-relay inbound, indexed like relayNames (the fan-out's order).
	relayNames []string
	relays     []CensusRelay
	// trace is the call's election/timeline collector, nil for outbound.
	trace *callTrace
}

// bindRelays names the fan-out's relays, in its index order, and attaches the
// call's trace. Called once, before the receive loop.
func (c *mediaCensus) bindRelays(names []string, trace *callTrace) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.relayNames = append([]string(nil), names...)
	c.relays = make([]CensusRelay, len(names))
	c.trace = trace
}

// relayDatagram attributes one datagram to the relay it came through, and
// relayRTP one that classified as RTP. An index outside the bound set is
// ignored.
func (c *mediaCensus) relayDatagram(relay int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if relay >= 0 && relay < len(c.relays) {
		c.relays[relay].Datagrams++
	}
}

func (c *mediaCensus) relayRTP(relay int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if relay >= 0 && relay < len(c.relays) {
		c.relays[relay].RTP++
	}
}

// duplicate counts RTP dropped as already seen through another relay.
func (c *mediaCensus) duplicate(relay int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snap.Duplicates++
	if relay >= 0 && relay < len(c.relays) {
		c.relays[relay].Duplicates++
	}
}

func newMediaCensus(callID string, inbound bool) *mediaCensus {
	return &mediaCensus{
		snap:           MediaCensus{CallID: callID, Inbound: inbound},
		failures:       map[string]uint64{},
		stunTypes:      map[string]uint64{},
		stunOtherTypes: map[string]uint64{},
		allocateErrors: map[string]uint64{},
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

// classifyCensusStun names one inbound STUN datagram, using the fork's own
// response parsers rather than a parser written beside them.
//
// Order matters only where the parsers overlap: IsAllocateOrBindingSuccess
// answers true for two distinct types, so the message type discriminates
// after it, and the binding REQUEST is matched explicitly rather than left to
// the default — a request is the one STUN type this stack acts on, and a
// classifier that let it fall into "other" would hide the consent path.
func classifyCensusStun(data []byte) string {
	mt, haveType := stun.StunMessageType(data)
	switch {
	case stun.IsAllocateError(data):
		return CensusStunAllocateError
	case stun.IsWhatsappPong(data, nil):
		return CensusStunPong
	case stun.IsAllocateOrBindingSuccess(data):
		if haveType && mt == stun.MsgBindingSuccess {
			return CensusStunBindingSuccess
		}
		return CensusStunAllocateSuccess
	case haveType && mt == stun.MsgBindingRequest:
		return CensusStunBindingRequest
	default:
		return CensusStunOther
	}
}

// stunMessage classifies one inbound STUN datagram and, when it is an
// allocate refusal, records its error code.
//
// It returns firstError true for the FIRST refusal of the call only, so the
// caller can say so loudly once rather than once per second for the rest of a
// three-minute call.
func (c *mediaCensus) stunMessage(data []byte, elapsedMS int64) (kind string, code uint16, codeFound bool, firstError bool) {
	kind = classifyCensusStun(data)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stunTypes[kind]++
	if kind == CensusStunOther {
		// The raw type, so an unexpected answer names itself. A datagram too
		// short to carry a type is its own reading and gets its own key
		// rather than a fabricated 0x0000.
		if mt, ok := stun.StunMessageType(data); ok {
			c.stunOtherTypes[fmt.Sprintf("0x%04x", mt)]++
		} else {
			c.stunOtherTypes["untyped"]++
		}
	}
	if kind != CensusStunAllocateError {
		return kind, 0, false, false
	}
	code, codeFound = stun.ParseStunErrorCode(data)
	key := "none"
	if codeFound {
		key = strconv.FormatUint(uint64(code), 10)
	}
	c.allocateErrors[key]++
	if c.snap.FirstAllocateError == nil {
		c.snap.FirstAllocateError = &CensusAllocateError{
			Code: code, CodeFound: codeFound, ElapsedMS: elapsedMS,
		}
		firstError = true
	}
	return kind, code, codeFound, firstError
}

// allocateInitialTx records the transaction id of the allocate sent at
// connect, which every later refresh is compared against.
func (c *mediaCensus) allocateInitialTx(txHex string) {
	c.mu.Lock()
	c.snap.AllocateTxInitial = txHex
	c.mu.Unlock()
}

// allocateRefreshSent records one 1 Hz refresh and whether it reused the
// initial transaction id. Observation only: the send already happened.
func (c *mediaCensus) allocateRefreshSent(txHex string) {
	c.mu.Lock()
	c.snap.AllocateRefreshes++
	c.snap.AllocateTxRefresh = txHex
	if txHex != "" && txHex == c.snap.AllocateTxInitial {
		c.snap.AllocateRefreshTxReused++
	}
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
	out.STUNTypes = copyCensusCounters(c.stunTypes)
	out.STUNOtherTypes = copyCensusCounters(c.stunOtherTypes)
	out.AllocateErrors = copyCensusCounters(c.allocateErrors)
	if c.snap.FirstAllocateError != nil {
		firstErr := *c.snap.FirstAllocateError
		out.FirstAllocateError = &firstErr
	}
	if c.snap.First != nil {
		first := *c.snap.First
		out.First = &first
	}
	if c.snap.Last != nil {
		last := *c.snap.Last
		out.Last = &last
	}
	if len(c.relays) > 0 {
		out.Relays = make(map[string]CensusRelay, len(c.relays))
		for i, r := range c.relays {
			name := c.relayNames[i]
			if _, dup := out.Relays[name]; dup || name == "" {
				name = fmt.Sprintf("%s#%d", name, i)
			}
			out.Relays[name] = r
		}
	}
	out.Trace = c.trace.snapshot()
	return out
}

// copyCensusCounters deep-copies one counter map, nil for empty so an absent
// breakdown reads as "none of this happened" rather than as an empty object.
func copyCensusCounters(src map[string]uint64) map[string]uint64 {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// renderCensusCounters renders a counter map as "k=v k=v", ordered: the named
// keys in the given order first, then anything else sorted, so two snapshots
// of one call line up column for column.
func renderCensusCounters(counts map[string]uint64, order []string) string {
	if len(counts) == 0 {
		return ""
	}
	var parts []string
	named := map[string]bool{}
	for _, key := range order {
		named[key] = true
		if n := counts[key]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", key, n))
		}
	}
	var rest []string
	for key := range counts {
		if !named[key] {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	for _, key := range rest {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, " ")
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
		Interface("stun_types", c.STUNTypes).
		Interface("stun_other_types", c.STUNOtherTypes).
		Interface("allocate_errors", c.AllocateErrors).
		Interface("first_allocate_error", c.FirstAllocateError).
		Uint64("allocate_refreshes", c.AllocateRefreshes).
		Str("allocate_tx_initial", c.AllocateTxInitial).
		Str("allocate_tx_refresh", c.AllocateTxRefresh).
		Bool("allocate_refresh_reuses_tx", c.RefreshReusesInitialTransactionID()).
		Interface("relays", c.Relays).
		Uint64("duplicates", c.Duplicates).
		Interface("trace", c.Trace).
		Msg("media census (temporary diagnostic, upstream issue #40)")
	e.c.diag.Emit("relay", map[string]any{
		"event": "media_census", "call_id": c.CallID, "final": c.Final,
		"elapsed_ms": c.ElapsedMS, "datagrams": c.Datagrams, "rtp": c.RTP,
		"audio": c.Audio, "unprotect_successes": c.UnprotectSuccesses,
		"frames_decoded": c.FramesDecoded, "failures": c.Failures,
		"stun_types": c.STUNTypes, "stun_other_types": c.STUNOtherTypes,
		"allocate_errors": c.AllocateErrors, "first_allocate_error": c.FirstAllocateError,
		"allocate_refreshes":  c.AllocateRefreshes,
		"allocate_tx_initial": c.AllocateTxInitial, "allocate_tx_refresh": c.AllocateTxRefresh,
		"relays": c.Relays, "duplicates": c.Duplicates, "trace": c.Trace,
	})
	if fn := e.c.mediaCensusObserver; fn != nil {
		fn(c)
	}
}
