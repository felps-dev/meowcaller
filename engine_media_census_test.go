package meowcaller

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTheCensusCountsEachStageSeparately is the whole point of the file in one
// test: a run where datagrams keep arriving and stop decrypting must be
// DISTINGUISHABLE from one where they stop arriving. Both are fed here and the
// two snapshots are asserted to differ in the way the diagnosis turns on.
func TestTheCensusCountsEachStageSeparately(t *testing.T) {
	// Run A: 10 datagrams, all audio RTP, 3 decrypt and the remaining 7 fail
	// the auth tag. This is the SRTP-state answer.
	a := newMediaCensus("c1", true)
	for i := 0; i < 10; i++ {
		a.datagram(170)
		a.classified(censusClassRTP)
		a.payload(mediaPayloadAudio)
		if i < 3 {
			a.decrypted(CensusPacket{Seq: uint16(100 + i), ROC: 0, SSRC: 7}, 320)
		} else {
			a.unprotectFailed(CensusFailAuthTag)
		}
	}
	snapA := a.snapshot(5000, false)

	// Run B: 3 datagrams, all of which decrypt, and then nothing arrives. This
	// is the transport answer.
	b := newMediaCensus("c1", true)
	for i := 0; i < 3; i++ {
		b.datagram(170)
		b.classified(censusClassRTP)
		b.payload(mediaPayloadAudio)
		b.decrypted(CensusPacket{Seq: uint16(100 + i), ROC: 0, SSRC: 7}, 320)
	}
	snapB := b.snapshot(5000, false)

	if snapA.FramesDecoded != 3 || snapB.FramesDecoded != 3 {
		t.Fatalf("both runs must decode the same 3 frames: A=%d B=%d",
			snapA.FramesDecoded, snapB.FramesDecoded)
	}
	// THE discriminator. Equal frame counts, different datagram counts: that
	// difference is the measurement, and a census that collapsed the two into
	// one number would be worth nothing.
	if snapA.Datagrams != 10 || snapB.Datagrams != 3 {
		t.Fatalf("datagrams = A:%d B:%d, want 10 and 3", snapA.Datagrams, snapB.Datagrams)
	}
	if snapA.Failures[CensusFailAuthTag] != 7 {
		t.Fatalf("auth-tag failures = %d, want 7", snapA.Failures[CensusFailAuthTag])
	}
	if len(snapB.Failures) != 0 {
		t.Fatalf("run B must report no failures at all: %v", snapB.Failures)
	}
	if snapA.UnprotectAttempts != 10 || snapA.UnprotectSuccesses != 3 {
		t.Fatalf("unprotect = %d/%d, want 3/10", snapA.UnprotectSuccesses, snapA.UnprotectAttempts)
	}
	if snapA.Bytes != 1700 || snapB.Bytes != 510 {
		t.Fatalf("bytes = A:%d B:%d, want 1700 and 510", snapA.Bytes, snapB.Bytes)
	}
}

// TestTheClassificationBreakdownSumsToTheDatagramCount pins the arithmetic the
// report's whole readability rests on. A breakdown that does not add up leaves
// a reader unable to tell a missing category from a lost packet.
func TestTheClassificationBreakdownSumsToTheDatagramCount(t *testing.T) {
	c := newMediaCensus("c1", false)
	for _, class := range []string{
		censusClassRTP, censusClassRTP, censusClassRTCP, censusClassSTUN,
		censusClassOther, censusClassGroupInvalid,
	} {
		c.datagram(100)
		c.classified(class)
	}
	s := c.snapshot(1000, true)
	if got := s.RTP + s.RTCP + s.STUN + s.Other + s.GroupInvalid; got != s.Datagrams {
		t.Fatalf("breakdown sums to %d, datagrams = %d", got, s.Datagrams)
	}
	if s.RTP != 2 || s.RTCP != 1 || s.STUN != 1 || s.Other != 1 || s.GroupInvalid != 1 {
		t.Fatalf("breakdown is wrong: %+v", s)
	}
	// An unrecognised class must land in Other rather than vanishing: the
	// relay's enum can grow and a dropped datagram would read as a transport
	// fault that never happened.
	c.datagram(100)
	c.classified("something-new")
	if s2 := c.snapshot(1000, true); s2.Other != 2 || s2.Datagrams != 7 {
		t.Fatalf("an unknown class did not land in Other: %+v", s2)
	}
}

// TestThePayloadBreakdownCountsEveryParsedRtpPacket covers the second
// breakdown, including the unknown payload type — which is the branch that
// would catch a peer renegotiating the codec mid-call.
func TestThePayloadBreakdownCountsEveryParsedRtpPacket(t *testing.T) {
	c := newMediaCensus("c1", true)
	c.payload(mediaPayloadAudio)
	c.payload(mediaPayloadAudio)
	c.payload(mediaPayloadVideo)
	c.payload(mediaPayloadAppData)
	c.payload(mediaPayloadKind(99))
	s := c.snapshot(0, false)
	if s.Audio != 2 || s.Video != 1 || s.AppData != 1 || s.UnknownPayload != 1 {
		t.Fatalf("payload breakdown is wrong: %+v", s)
	}
	// An unparsable RTP header is NOT an unprotect attempt: it never reached
	// the audio registry, and counting it would make the attempts/successes
	// ratio disagree with the audio count for a non-crypto reason.
	c.rtpUnparsable()
	s = c.snapshot(0, false)
	if s.UnprotectAttempts != 0 {
		t.Fatalf("an unparsable header was counted as an unprotect attempt: %+v", s)
	}
	if s.Failures[CensusFailUnparsableRTP] != 1 {
		t.Fatalf("an unparsable header was not recorded at all: %v", s.Failures)
	}
}

// TestTheFirstAndLastDecryptedPacketBracketTheStream pins the pair that says
// WHERE a stalled stream stopped. First must never move once set — a census
// whose First followed the stream could not report the beginning of the gap.
func TestTheFirstAndLastDecryptedPacketBracketTheStream(t *testing.T) {
	c := newMediaCensus("c1", true)
	if s := c.snapshot(0, false); s.First != nil || s.Last != nil {
		t.Fatalf("a call with nothing decrypted must report neither bracket: %+v", s)
	}
	c.decrypted(CensusPacket{Seq: 65534, ROC: 0, SSRC: 7}, 320)
	c.decrypted(CensusPacket{Seq: 65535, ROC: 0, SSRC: 7}, 320)
	// Past the 16-bit wrap: seq goes DOWN while the ROC goes up, which is the
	// one case where a regression is not a regression.
	c.decrypted(CensusPacket{Seq: 0, ROC: 1, SSRC: 7}, 320)
	s := c.snapshot(0, true)
	if s.First == nil || s.First.Seq != 65534 || s.First.ROC != 0 {
		t.Fatalf("First moved or is wrong: %+v", s.First)
	}
	if s.Last == nil || s.Last.Seq != 0 || s.Last.ROC != 1 {
		t.Fatalf("Last is wrong: %+v", s.Last)
	}
	// The wrap counts as a regression, and that is DELIBERATE rather than a
	// bug to fix here: the counter is raw evidence about the estimator's own
	// input, and a census that silently forgave the wrap would hide the one
	// sequence pattern the ROC estimator branches on. The ROC in First/Last is
	// what tells a reader which it was.
	if s.SeqRegressions != 1 {
		t.Fatalf("seq regressions = %d, want the wrap counted once", s.SeqRegressions)
	}
}

// TestCryptoSuccessWithNoSamplesIsNotADecodedFrame separates the two things
// the integrator's own frames_in cannot separate. A packet that authenticates
// and decrypts and then yields nothing puts the fault in the codec, not in
// SRTP, and that is a different next step.
func TestCryptoSuccessWithNoSamplesIsNotADecodedFrame(t *testing.T) {
	c := newMediaCensus("c1", true)
	c.decrypted(CensusPacket{Seq: 1, SSRC: 7}, 320)
	c.decrypted(CensusPacket{Seq: 2, SSRC: 7}, 0)
	s := c.snapshot(0, true)
	if s.UnprotectSuccesses != 2 {
		t.Fatalf("both packets decrypted: successes = %d", s.UnprotectSuccesses)
	}
	if s.FramesDecoded != 1 {
		t.Fatalf("frames decoded = %d, want 1", s.FramesDecoded)
	}
	if s.Failures[CensusFailDecodeEmpty] != 1 {
		t.Fatalf("the empty decode was not recorded: %v", s.Failures)
	}
}

// TestASnapshotDoesNotShareStateWithTheCollector is why snapshot deep-copies.
// The observer reads the value on its own goroutine while the receive loop
// keeps counting, so a shared map or a shared pointer is a data race on the
// one measurement this whole file exists to take.
func TestASnapshotDoesNotShareStateWithTheCollector(t *testing.T) {
	c := newMediaCensus("c1", true)
	c.unprotectFailed(CensusFailAuthTag)
	c.decrypted(CensusPacket{Seq: 5, ROC: 2, SSRC: 7}, 320)
	s := c.snapshot(100, false)

	c.unprotectFailed(CensusFailAuthTag)
	c.decrypted(CensusPacket{Seq: 9, ROC: 2, SSRC: 7}, 320)

	if s.Failures[CensusFailAuthTag] != 1 {
		t.Fatalf("the snapshot's map followed the collector: %v", s.Failures)
	}
	if s.Last.Seq != 5 {
		t.Fatalf("the snapshot's Last followed the collector: %+v", s.Last)
	}
	// And the counters themselves are cumulative, so a later snapshot carries
	// the earlier one's counts too — that is what makes two snapshots an
	// interval by subtraction.
	if later := c.snapshot(200, true); later.Failures[CensusFailAuthTag] != 2 || later.UnprotectSuccesses != 2 {
		t.Fatalf("a later snapshot is not cumulative: %+v", later)
	}
}

// TestTheEmittedCensusCarriesNoSecretOrPayload asserts the production-safety
// rule over the EMITTED FORM — the JSON and the Summary line — rather than
// field by field, because a field added later is exactly the leak a
// field-by-field assertion does not see. It runs on a live credential.
func TestTheEmittedCensusCarriesNoSecretOrPayload(t *testing.T) {
	c := newMediaCensus("call-abc", true)
	c.datagram(170)
	c.classified(censusClassRTP)
	c.payload(mediaPayloadAudio)
	c.decrypted(CensusPacket{Seq: 42, ROC: 1, SSRC: 0xDEAD}, 320)
	c.unprotectFailed(CensusFailAuthTag)
	c.rtcpAuthFailed()
	c.stunBindingAnswered()
	s := c.snapshot(5000, true)

	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The allowlist is over KEYS, not over values: a value is a number or a
	// failure-kind name, and every key a reader is allowed to see is named
	// here. A new field fails this test until somebody states that it is safe.
	allowed := map[string]bool{
		"call_id": true, "inbound": true, "final": true, "elapsed_ms": true,
		"datagrams": true, "bytes": true, "rtp": true, "rtcp": true,
		"stun": true, "other": true, "group_invalid": true, "audio": true,
		"video": true, "app_data": true, "unknown_payload": true,
		"unprotect_attempts": true, "unprotect_successes": true,
		"failures": true, "frames_decoded": true, "seq_regressions": true,
		"first": true, "last": true, "seq": true, "roc": true, "ssrc": true,
		"rtcp_auth_failures": true, "stun_bindings_answered": true,
	}
	for _, kind := range censusFailKinds {
		allowed[kind] = true
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The premise, asserted beside the property: a probe that found nothing
	// would pass the loop below unconditionally.
	if len(probe) < 10 {
		t.Fatalf("the emitted form has only %d keys; the guard is not looking at anything", len(probe))
	}
	for key := range probe {
		if !allowed[key] {
			t.Fatalf("the emitted census carries an undeclared field %q — state that it is safe to log on a live credential, or do not emit it", key)
		}
	}
	// Nested objects too: First/Last and the failure map are where a
	// payload-shaped field would most plausibly be added.
	var nested map[string]map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &nested); err == nil {
		for parent, child := range nested {
			for key := range child {
				if !allowed[key] {
					t.Fatalf("%s carries an undeclared field %q", parent, key)
				}
			}
		}
	}
	// And the words no diagnostic may ever contain — over the Summary line
	// and over every STRING VALUE in the JSON, which is where a leak would
	// land. Not over the key names: the allowlist above already refuses an
	// undeclared key, and a value-shaped scan over keys only collides with
	// the counters' own honest names (unknown_payload is a count).
	scanned := []string{s.Summary()}
	for _, raw := range probe {
		var str string
		if json.Unmarshal(raw, &str) == nil {
			scanned = append(scanned, str)
		}
	}
	for _, forbidden := range []string{
		"key", "secret", "pcm", "payload", "rms", "sample", "token", "plaintext", "hex",
	} {
		for _, text := range scanned {
			if strings.Contains(strings.ToLower(text), forbidden) {
				t.Fatalf("the emitted census contains %q: %s", forbidden, text)
			}
		}
	}
	if !strings.Contains(s.Summary(), "frames=1") || !strings.Contains(s.Summary(), "auth_tag=1") {
		t.Fatalf("the summary does not carry the numbers it is read for: %s", s.Summary())
	}
}

// TestTheObserverIsOptional: no observer installed is the production default
// for every integrator but this one, and it must cost nothing and crash
// nothing.
func TestTheObserverIsOptional(t *testing.T) {
	cfg := resolveConfig(nil)
	if cfg.mediaCensusObserver != nil {
		t.Fatal("the zero configuration installed an observer")
	}
	var got MediaCensus
	cfg = resolveConfig([]Option{WithMediaCensusObserver(func(c MediaCensus) { got = c })})
	if cfg.mediaCensusObserver == nil {
		t.Fatal("WithMediaCensusObserver did not install the observer")
	}
	cfg.mediaCensusObserver(MediaCensus{CallID: "c1", Datagrams: 4})
	if got.CallID != "c1" || got.Datagrams != 4 {
		t.Fatalf("the observer did not receive the report: %+v", got)
	}
}
