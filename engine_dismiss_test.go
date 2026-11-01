package meowcaller

import (
	"context"
	"errors"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// Real multi-device ringing — which of a callee's devices rings, which
// answers, and whether a terminate addressed to one of them silences it — is
// not reproducible here: there is no server and no callee. These pin the
// fork's half: which devices a terminate is addressed to, with which reason,
// and that the device that answered is never one of them.

// ringingOn is an outgoing 1:1 call whose offer rang the given devices of the
// callee, recording every stanza it sends.
func ringingOn(devices ...uint16) (*engine, *Call, *sentNodes) {
	eng, call := testEngineWithOutgoingCall()
	sent := &sentNodes{}
	eng.sendCallNode = sent.send
	m := eng.calls["CID"]
	m.trace = newCallTrace(time.Now())
	jids := make([]types.JID, 0, len(devices))
	for _, d := range devices {
		jids = append(jids, calleeDevice(d))
	}
	m.recordOffer(jids)
	return eng, call, sent
}

type sentTerminate struct {
	to        types.JID
	id        string
	reason    string
	hasReason bool
	creator   types.JID
}

func terminates(s *sentNodes) []sentTerminate {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sentTerminate
	for _, n := range s.nodes {
		kids := n.GetChildren()
		if n.Tag != "call" || len(kids) != 1 || kids[0].Tag != "terminate" {
			continue
		}
		to, _ := n.Attrs["to"].(types.JID)
		id, _ := n.Attrs["id"].(string)
		reason, hasReason := kids[0].Attrs["reason"].(string)
		creator, _ := kids[0].Attrs["call-creator"].(types.JID)
		out = append(out, sentTerminate{to: to, id: id, reason: reason, hasReason: hasReason, creator: creator})
	}
	return out
}

// devicesTold is the device numbers the terminates went to, failing the test
// on any terminate that is not addressed to one device of the callee or that
// carries the wrong reason.
func devicesTold(t *testing.T, s *sentNodes, wantReason string) map[uint16]int {
	t.Helper()
	told := map[uint16]int{}
	ids := map[string]bool{}
	for _, term := range terminates(s) {
		if term.to.User != peerJID().User || term.to.Server != peerJID().Server {
			t.Fatalf("terminate addressed to %s, which is not a device of the callee", term.to)
		}
		if wantReason == "" && term.hasReason {
			t.Errorf("terminate to %s carries reason %q, want none", term.to, term.reason)
		}
		if wantReason != "" && term.reason != wantReason {
			t.Errorf("terminate to %s carries reason %q, want %q", term.to, term.reason, wantReason)
		}
		if term.creator != creatorJID() {
			t.Errorf("terminate to %s names creator %s, want %s", term.to, term.creator, creatorJID())
		}
		if term.id == "" || ids[term.id] {
			t.Errorf("terminate to %s has stanza id %q: every stanza needs its own", term.to, term.id)
		}
		ids[term.id] = true
		told[term.to.Device]++
	}
	return told
}

func acceptFrom(from types.JID) *events.CallAccept {
	return &events.CallAccept{
		BasicCallMeta: types.BasicCallMeta{CallID: "CID", From: from, CallCreator: creatorJID()},
		Data:          &waBinary.Node{Tag: "accept"},
	}
}

func assertTold(t *testing.T, told map[uint16]int, want ...uint16) {
	t.Helper()
	if len(told) != len(want) {
		t.Fatalf("told devices %v, want exactly %v", told, want)
	}
	for _, d := range want {
		if told[d] != 1 {
			t.Fatalf("told devices %v, want exactly one terminate each to %v", told, want)
		}
	}
}

// ANSWERING ON THE PHONE SILENCES THE OTHERS AND NEVER THE PHONE. A
// terminate that reached device 0 here would hang up the call that was just
// answered.
func TestAnsweringOnTheFirstDeviceDismissesTheOthersOnly(t *testing.T) {
	eng, call, sent := ringingOn(0, 5, 92)
	reason := endReason(call)

	eng.onAccept(acceptFrom(calleeDevice(0)))

	told := devicesTold(t, sent, terminateReasonAcceptedElsewhere)
	if told[0] != 0 {
		t.Fatalf("the answering device 0 was sent %d terminate(s); that ends the live call", told[0])
	}
	assertTold(t, told, 5, 92)
	assertLive(t, eng, call, reason)
	if !call.hasPeerAccepted() {
		t.Fatal("the accept was not recorded")
	}
}

// Same rule for a companion that answers: the phone is the sibling now.
func TestAnsweringOnACompanionDismissesThePhone(t *testing.T) {
	eng, _, sent := ringingOn(0, 5, 92)

	eng.onAccept(acceptFrom(calleeDevice(5)))

	told := devicesTold(t, sent, terminateReasonAcceptedElsewhere)
	if told[5] != 0 {
		t.Fatalf("the answering device 5 was sent a terminate")
	}
	assertTold(t, told, 0, 92)
}

// An accept whose sender cannot be found among the offered devices — another
// namespace, another user — gives no way to tell the answerer from its
// siblings. Nothing is sent, because a guess could be the live call.
func TestAnAnswererThatWasNotOfferedDismissesNothing(t *testing.T) {
	eng, call, sent := ringingOn(0, 5)
	reason := endReason(call)
	pn := types.JID{User: "5511988887777", Server: types.DefaultUserServer}

	eng.onAccept(acceptFrom(pn))

	if got := terminates(sent); len(got) != 0 {
		t.Fatalf("sent %d terminate(s) on an accept from a device the offer never rang: %+v", len(got), got)
	}
	assertLive(t, eng, call, reason)
}

// An accept from an unqualified address reads as device 0, while the relay
// already elected companion 7 as the peer. Either could be the answerer, so
// both are spared and only the device that is certainly a sibling is told.
func TestAnAmbiguousAnswererSparesEveryCandidate(t *testing.T) {
	eng, _, sent := ringingOn(0, 7, 92)
	m := eng.calls["CID"]
	m.peerLID = peerJID().String()
	m.rekeyPeer = func(string) error { return nil }
	eng.onRelay("CID", &waBinary.Node{
		Tag:   "relay",
		Attrs: waBinary.Attrs{"peer_pid": "2"},
		Content: []waBinary.Node{
			{Tag: "participant", Attrs: waBinary.Attrs{"pid": "2", "jid": calleeDevice(7)}},
		},
	})

	eng.onAccept(acceptFrom(peerJID()))

	told := devicesTold(t, sent, terminateReasonAcceptedElsewhere)
	if told[0] != 0 || told[7] != 0 {
		t.Fatalf("told %v: a device that may be the answerer was sent a terminate", told)
	}
	assertTold(t, told, 92)
}

// A repeated accept is not a second dismissal.
func TestASecondAcceptDismissesNobodyAgain(t *testing.T) {
	eng, _, sent := ringingOn(0, 5)

	eng.onAccept(acceptFrom(calleeDevice(0)))
	eng.onAccept(acceptFrom(calleeDevice(0)))

	assertTold(t, devicesTold(t, sent, terminateReasonAcceptedElsewhere), 5)
}

// GIVING UP BEFORE A PICKUP TELLS EVERY DEVICE THE OFFER RANG. This is the
// integrator's ring deadline too: it ends an unanswered call through Hangup.
// One terminate per device, no reason, and nothing to the bare peer.
func TestHangingUpARingingCallTerminatesEveryOfferedDevice(t *testing.T) {
	_, call, sent := ringingOn(0, 5, 92)
	reason := endReason(call)

	if err := call.Hangup(); err != nil {
		t.Fatal(err)
	}

	// Exactly one each: the bare peer is device 0's JID, so a bare-peer
	// terminate sent as well would show as a second one to device 0.
	assertTold(t, devicesTold(t, sent, ""), 0, 5, 92)
	assertEnded(t, call, reason, "hangup")
}

// After a pickup the terminate goes to the device that answered, alone: the
// others were already dismissed at the accept.
func TestHangingUpAnAnsweredCallTerminatesOnlyTheAnsweringDevice(t *testing.T) {
	eng, call, sent := ringingOn(0, 5, 92)
	reason := endReason(call)
	eng.onAccept(acceptFrom(calleeDevice(5)))
	sent.mu.Lock()
	sent.nodes = nil
	sent.mu.Unlock()

	if err := call.Hangup(); err != nil {
		t.Fatal(err)
	}

	got := terminates(sent)
	if len(got) != 1 || !sameDevice(got[0].to, calleeDevice(5)) {
		t.Fatalf("terminates after the pickup = %+v, want exactly one, to the answering device 5", got)
	}
	assertEnded(t, call, reason, "hangup")
}

// A send that fails on one device still tries the rest, still ends the call
// locally, and reports the failure.
func TestARingingHangupTriesEveryDeviceWhenOneSendFails(t *testing.T) {
	eng, call, sent := ringingOn(0, 5)
	reason := endReason(call)
	calls := 0
	eng.sendCallNode = func(ctx context.Context, node waBinary.Node) error {
		calls++
		_ = sent.send(ctx, node)
		if calls == 1 {
			return errors.New("network unavailable")
		}
		return nil
	}

	if err := call.Hangup(); err == nil {
		t.Fatal("Hangup returned nil after a failed terminate")
	}
	if calls != 2 {
		t.Fatalf("attempted %d terminates, want one per offered device (2)", calls)
	}
	assertEnded(t, call, reason, "hangup")
}

// A FINAL REJECT TELLS THE REST. The phone declined; the companion that is
// still ringing is told rejected_elsewhere, and the phone is not told again.
func TestAFinalRejectDismissesTheOtherDevices(t *testing.T) {
	eng, call, sent := ringingOn(0, 5, 92)
	reason := endReason(call)

	eng.onReject(rejectFrom(0, nil))

	assertEnded(t, call, reason, "rejected")
	assertTold(t, devicesTold(t, sent, terminateReasonRejectedElsewhere), 5, 92)
}

// A reject that does NOT end the call dismisses nobody: the phone is still
// ringing and must stay ringing.
func TestAnIgnoredRejectDismissesNobody(t *testing.T) {
	eng, call, sent := ringingOn(0, 92)
	reason := endReason(call)

	eng.onReject(rejectFrom(92, nil))

	assertLive(t, eng, call, reason)
	if got := terminates(sent); len(got) != 0 {
		t.Fatalf("an ignored companion reject sent %d terminate(s): %+v", len(got), got)
	}
}

// Nothing in this file applies to a call we RECEIVED: the callee never
// dismisses its own devices.
func TestAnInboundCallDismissesNobody(t *testing.T) {
	eng, call, sent := ringingOn(0, 5)
	eng.calls["CID"].direction = CallDirectionIncoming

	if err := call.Hangup(); err != nil {
		t.Fatal(err)
	}
	got := terminates(sent)
	if len(got) != 1 || got[0].to != peerJID() {
		t.Fatalf("inbound hang-up sent %+v, want one terminate to the caller", got)
	}
}

// ---------------------------------------------------------------------------
// Every way a call ends names a reason
// ---------------------------------------------------------------------------

// A callee hanging up sends <terminate> with no reason attribute, and
// whatsmeow reports that as "". Production's outbound call
// 327ED8CECB65F97AFAAFF74125619AE5 reached the integrator as reason="" that
// way. Both directions, because the stanza is the same.
func TestAPeerTerminateWithNoReasonIsAHangup(t *testing.T) {
	for _, dir := range []CallDirection{CallDirectionOutgoing, CallDirectionIncoming} {
		eng, call := testEngineWithOutgoingCall()
		eng.calls["CID"].direction = dir
		reason := endReason(call)

		eng.onTerminate("CID", "")

		assertEnded(t, call, reason, "hangup")
	}
}

// A reason the peer did send is its own and passes through untouched.
func TestAPeerTerminateReasonPassesThrough(t *testing.T) {
	eng, call := testEngineWithOutgoingCall()
	reason := endReason(call)

	eng.onTerminate("CID", "timeout")

	assertEnded(t, call, reason, "timeout")
}

// Every entry point that ends a 1:1 call hands OnEnd a non-empty reason.
func TestEveryEndPathNamesAReason(t *testing.T) {
	ends := map[string]func(*engine, *Call){
		"our hangup":     func(_ *engine, c *Call) { _ = c.Hangup() },
		"our reject":     func(_ *engine, c *Call) { _ = c.Reject() },
		"peer reject":    func(e *engine, _ *Call) { e.onReject(rejectFrom(0, nil)) },
		"peer terminate": func(e *engine, _ *Call) { e.onTerminate("CID", "") },
		"server error ack": func(e *engine, _ *Call) {
			e.onCallAck(&waBinary.Node{
				Tag:     "ack",
				Attrs:   waBinary.Attrs{"error": "404"},
				Content: []waBinary.Node{{Tag: "error", Attrs: waBinary.Attrs{"call-id": "CID"}}},
			})
		},
	}
	for name, end := range ends {
		eng, call, _ := ringingOn(0)
		var got *string
		fired := false
		call.OnEnd(func(r string) { fired = true; got = &r })

		end(eng, call)

		if !fired || got == nil || *got == "" {
			t.Errorf("%s: OnEnd fired=%v with reason %v, want a non-empty reason", name, fired, got)
		}
	}
}
