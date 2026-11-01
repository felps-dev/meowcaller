package meowcaller

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestTheCensusNamesTheRelaysTheCallerProbedAndWhichWereSkipped is diagnostic
// 1: the caller's probed relay names beside the offer's, and which were
// skipped as outside it. A name in skipped_relays on one of OUR calls is the
// out-of-offer edge #26 describes; none, call after call, kills that reading.
func TestTheCensusNamesTheRelaysTheCallerProbedAndWhichWereSkipped(t *testing.T) {
	eng, _, _ := testEngineWithIncomingCall()
	m := eng.calls["CID"]
	m.relay = twoRelayOffer()
	m.trace = newCallTrace(time.Now())
	m.trace.offerRelays(m.relay)
	eng.sendCallNode = (&sentNodes{}).send

	eng.onRelayLatency(relayLatencyEvent("gig4c02", "poa1c01", "gru2c01"))
	eng.onRelayLatency(relayLatencyEvent("poa1c01", "gru2c01"))

	census := newMediaCensus("CID", true)
	census.bindRelays([]string{"gig4c02", "gru2c01"}, m.trace)
	snap := census.snapshot(1000, false)
	if snap.Trace == nil {
		t.Fatal("an inbound call's census carries no trace")
	}
	if got := strings.Join(snap.Trace.OfferRelays, ","); got != "gig4c02,gru2c01" {
		t.Fatalf("offer_relays = %q", got)
	}
	if got := renderCensusCounters(snap.Trace.ProbedRelays, nil); got != "gig4c02=1 gru2c01=2 poa1c01=2" {
		t.Fatalf("probed_relays = %q", got)
	}
	if got := renderCensusCounters(snap.Trace.SkippedRelays, nil); got != "poa1c01=2" {
		t.Fatalf("skipped_relays = %q, want the out-of-offer relay counted on both stanzas", got)
	}
	if !strings.Contains(snap.Summary(), "skipped=[poa1c01=2]") {
		t.Fatalf("summary does not name the skipped relay: %s", snap.Summary())
	}
}

// TestTheTimelinePutsOfferMediaAnswerAndAcceptOnOneClock is diagnostic 2,
// driven through the engine's own paths: early media at the offer, the
// caller's mute_v2 while ringing, Answer, the deferred accept it sends, and
// the first inbound RTP.
func TestTheTimelinePutsOfferMediaAnswerAndAcceptOnOneClock(t *testing.T) {
	req := &socketRequests{}
	eng, call, _ := earlyMediaEngine(req.factory)
	trace := newCallTrace(time.Now())
	eng.calls["CID"].trace = trace

	eng.ringInbound("CID", peerJID(), creatorJID(), false, call)
	eng.onCallRaw(muteV2Node())
	time.Sleep(5 * time.Millisecond)
	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	eng.onFirstInboundRTP("CID", call)

	tl := trace.snapshot().Timeline
	for name, v := range map[string]*int64{
		"media_start": tl.MediaStartMS, "mute_v2": tl.MuteV2MS, "answer": tl.AnswerMS,
		"accept_sent": tl.AcceptSentMS, "first_rtp": tl.FirstRTPMS,
	} {
		if v == nil {
			t.Fatalf("timeline has no %s: %s", name, tl.String())
		}
	}
	if !(*tl.MediaStartMS <= *tl.MuteV2MS && *tl.MuteV2MS < *tl.AnswerMS && *tl.AnswerMS <= *tl.AcceptSentMS) {
		t.Fatalf("timeline out of order: %s", tl.String())
	}
	if tl.CallKeyMS != nil {
		t.Fatalf("callkey marked without an offer having been decrypted: %s", tl.String())
	}
}

// TestTheTraceAndRelayFieldsAreSafeToLog: relay names and millisecond
// offsets, nothing else, on the emitted form.
func TestTheTraceAndRelayFieldsAreSafeToLog(t *testing.T) {
	trace := newCallTrace(time.Now())
	trace.offerRelays(twoRelayOffer())
	trace.probes([]string{"gig4c02", "poa1c01"}, []string{"poa1c01"})
	trace.mark(traceCallKey)
	trace.mark(traceAnswer)
	c := newMediaCensus("CID", true)
	c.bindRelays([]string{"gig4c02", "gru2c01"}, trace)
	c.relayDatagram(0)
	c.relayRTP(0)
	c.duplicate(1)

	encoded, err := json.Marshal(c.snapshot(10, true))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatal(err)
	}
	var relays map[string]map[string]json.RawMessage
	if err := json.Unmarshal(top["relays"], &relays); err != nil || len(relays) != 2 {
		t.Fatalf("relays did not encode as two relay objects: %s (%v)", top["relays"], err)
	}
	for name, fields := range relays {
		for key := range fields {
			if key != "datagrams" && key != "rtp" && key != "duplicates" {
				t.Fatalf("relay %s carries an undeclared field %q", name, key)
			}
		}
	}
	var tr map[string]json.RawMessage
	if err := json.Unmarshal(top["trace"], &tr); err != nil || len(tr) == 0 {
		t.Fatalf("trace did not encode: %s (%v)", top["trace"], err)
	}
	allowedTrace := map[string]bool{"offer_relays": true, "probed_relays": true, "skipped_relays": true, "timeline": true}
	for key := range tr {
		if !allowedTrace[key] {
			t.Fatalf("trace carries an undeclared field %q", key)
		}
	}
	var tl map[string]json.RawMessage
	if err := json.Unmarshal(tr["timeline"], &tl); err != nil || len(tl) != 2 {
		t.Fatalf("timeline = %s (%v), want the two marked milestones", tr["timeline"], err)
	}
	for key := range tl {
		if !strings.HasSuffix(key, "_ms") {
			t.Fatalf("timeline carries a non-offset field %q", key)
		}
	}
}
