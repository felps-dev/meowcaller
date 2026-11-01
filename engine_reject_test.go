package meowcaller

import (
	"context"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// placedCallTo builds an outgoing 1:1 call whose offer went to the given
// device numbers of the callee, with a trace and a reject observer, the way
// placeCall leaves one.
func placedCallTo(devices ...uint16) (*engine, *Call, *[]CallRejectReport) {
	eng, call := testEngineWithOutgoingCall()
	var reports []CallRejectReport
	eng.c.callRejectObserver = func(r CallRejectReport) { reports = append(reports, r) }
	m := eng.calls["CID"]
	m.offeredDevices = devices
	m.trace = newCallTrace(time.Now())
	return eng, call, &reports
}

func calleeDevice(device uint16) types.JID {
	j := peerJID()
	j.Device = device
	return j
}

// rejectFrom is the stanza production received: count="0", no reason.
func rejectFrom(device uint16, attrs waBinary.Attrs) *events.CallReject {
	all := waBinary.Attrs{"call-id": "CID", "call-creator": creatorJID().String(), "count": "0"}
	for k, v := range attrs {
		all[k] = v
	}
	return &events.CallReject{
		BasicCallMeta: types.BasicCallMeta{CallID: "CID", From: calleeDevice(device), CallCreator: creatorJID()},
		Data:          &waBinary.Node{Tag: "reject", Attrs: all},
	}
}

func preacceptFrom(device uint16) *events.CallPreAccept {
	return &events.CallPreAccept{
		BasicCallMeta: types.BasicCallMeta{CallID: "CID", From: calleeDevice(device), CallCreator: creatorJID()},
		Data:          &waBinary.Node{Tag: "preaccept"},
	}
}

func endReason(call *Call) *string {
	var reason string
	call.OnEnd(func(r string) { reason = r })
	return &reason
}

func assertLive(t *testing.T, eng *engine, call *Call, reason *string) {
	t.Helper()
	if call.State() == CallPhaseEnded || eng.lookup("CID") == nil || *reason != "" {
		t.Fatalf("the call was torn down (phase %d, reason %q)", call.State(), *reason)
	}
}

func assertEnded(t *testing.T, call *Call, reason *string, want string) {
	t.Helper()
	if call.State() != CallPhaseEnded || *reason != want {
		t.Fatalf("phase %d reason %q, want Ended with %q", call.State(), *reason, want)
	}
}

// Production, three times: the offer went to the callee's phone and to a
// companion; the companion (:92) rejected in under half a second with
// count="0" and no reason, and the phone preaccepted AFTER that reject and
// was still ringing. The call must still be up for the phone to answer.
func TestCompanionRejectDoesNotEndARingingCall(t *testing.T) {
	eng, call, reports := placedCallTo(0, 92)
	reason := endReason(call)

	eng.onReject(rejectFrom(92, nil))
	assertLive(t, eng, call, reason)
	eng.onPreAccept(preacceptFrom(0))
	assertLive(t, eng, call, reason)
	if call.State() != CallPhaseRinging {
		t.Fatalf("phase = %d, want Ringing after the phone's preaccept", call.State())
	}

	if len(*reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(*reports))
	}
	r := (*reports)[0]
	if r.Final || r.Rule != RejectRuleCompanion || r.Device != 92 || r.Count != "0" || r.Reason != "" || !r.Outgoing {
		t.Fatalf("report = %+v, want an ignored companion reject from :92 with count 0", r)
	}
	tr := eng.calls["CID"].trace.snapshot()
	if len(tr.DeviceRejects) != 1 || tr.DeviceRejects[0].Device != 92 || tr.DeviceRejects[0].Final ||
		tr.DeviceRejects[0].Count != "0" || tr.DeviceRejects[0].Rule != RejectRuleCompanion {
		t.Fatalf("trace rejects = %+v, want the ignored :92 reject", tr.DeviceRejects)
	}
}

// The phone declining is the callee declining.
func TestPrimaryDeviceRejectEndsTheCall(t *testing.T) {
	eng, call, reports := placedCallTo(0, 92)
	reason := endReason(call)
	eng.onPreAccept(preacceptFrom(0))

	eng.onReject(rejectFrom(0, nil))
	assertEnded(t, call, reason, "rejected")
	if r := (*reports)[0]; !r.Final || r.Rule != RejectRulePrimary || r.Device != 0 {
		t.Fatalf("report = %+v, want a final primary-device reject", r)
	}
}

// A companion that RANG (preaccepted) and then declined is a person
// declining on it.
func TestARangCompanionRejectEndsTheCall(t *testing.T) {
	eng, call, reports := placedCallTo(0, 5)
	reason := endReason(call)
	eng.onPreAccept(preacceptFrom(5))

	eng.onReject(rejectFrom(5, nil))
	assertEnded(t, call, reason, "rejected")
	if r := (*reports)[0]; !r.Final || r.Rule != RejectRuleRangDevice || r.Device != 5 {
		t.Fatalf("report = %+v, want a final preaccepted-device reject", r)
	}
}

// Once nothing is left ringing the call is over, whatever each device said
// about itself.
func TestTheLastDeviceToRejectEndsTheCall(t *testing.T) {
	eng, call, reports := placedCallTo(0, 92)
	reason := endReason(call)

	eng.onReject(rejectFrom(92, nil))
	assertLive(t, eng, call, reason)
	eng.onReject(rejectFrom(0, waBinary.Attrs{"reason": "busy"}))
	assertEnded(t, call, reason, "rejected")
	if r := (*reports)[1]; !r.Final || r.Rule != RejectRuleAllDevices || r.Reason != "busy" {
		t.Fatalf("report = %+v, want final on every device rejected", r)
	}
}

// busy and enc speak for one device, the phone included: a Desktop that is
// still ringing may answer.
func TestABusyPhoneLeavesTheCompanionsRinging(t *testing.T) {
	eng, call, reports := placedCallTo(0, 5)
	reason := endReason(call)

	eng.onReject(rejectFrom(0, waBinary.Attrs{"reason": "busy"}))
	assertLive(t, eng, call, reason)
	if r := (*reports)[0]; r.Final || r.Rule != RejectRuleDeviceBusy {
		t.Fatalf("report = %+v, want an ignored busy reject", r)
	}
}

// An ignored reject must never leave a call ringing forever: the caller's
// own Hangup — what the integrator's ring deadline calls — and the peer's
// terminate still end it.
func TestACallWhoseOnlyRejectsWereIgnoredStillEnds(t *testing.T) {
	t.Run("hangup (the ring deadline)", func(t *testing.T) {
		eng, call, _ := placedCallTo(0, 92)
		var sent []waBinary.Node
		eng.sendCallNode = func(_ context.Context, n waBinary.Node) error { sent = append(sent, n); return nil }
		reason := endReason(call)
		eng.onReject(rejectFrom(92, nil))
		assertLive(t, eng, call, reason)

		if err := eng.hangup(call); err != nil {
			t.Fatal(err)
		}
		assertEnded(t, call, reason, "hangup")
		if len(sent) != 1 || len(sent[0].GetChildren()) != 1 || sent[0].GetChildren()[0].Tag != "terminate" {
			t.Fatalf("sent = %+v, want one <terminate>", sent)
		}
	})
	t.Run("terminate", func(t *testing.T) {
		eng, call, _ := placedCallTo(0, 92)
		reason := endReason(call)
		eng.onReject(rejectFrom(92, nil))
		eng.onTerminate("CID", "timeout")
		assertEnded(t, call, reason, "timeout")
	})
}

// After the callee picked up, a device declining changes nothing.
func TestARejectAfterThePickupIsIgnored(t *testing.T) {
	eng, call, reports := placedCallTo(0, 92)
	reason := endReason(call)
	call.markPeerAccepted()

	eng.onReject(rejectFrom(0, nil))
	assertLive(t, eng, call, reason)
	if r := (*reports)[0]; r.Final || r.Rule != RejectRuleAnswered {
		t.Fatalf("report = %+v, want an ignored post-accept reject", r)
	}
}

// The inbound mirror (upstream PR #47): on a call we RECEIVED, a reject is
// another device of this account declining for itself — the owner's phone,
// or a hosted companion that rejects every call. Our answered call stays up
// until the caller terminates it.
func TestAnotherDeviceOfOursRejectingDoesNotEndAnInboundCall(t *testing.T) {
	eng, call, reports := placedCallTo()
	eng.calls["CID"].direction = CallDirectionIncoming
	call.setPhase(CallPhaseActive)
	reason := endReason(call)

	eng.onReject(rejectFrom(0, waBinary.Attrs{"reason": "unavailable"}))
	assertLive(t, eng, call, reason)
	if r := (*reports)[0]; r.Final || r.Rule != RejectRuleInbound || r.Outgoing {
		t.Fatalf("report = %+v, want an ignored inbound reject", r)
	}
	eng.onTerminate("CID", "")
	if call.State() != CallPhaseEnded {
		t.Fatalf("phase = %d after terminate, want Ended", call.State())
	}
}

// An offer with no recorded devices is never "every device rejected" —
// that would make the first reject final, which is the bug.
func TestAnUnknownDeviceSetIsNeverEveryDevice(t *testing.T) {
	if everyDeviceRejected(nil, map[uint16]bool{92: true}) {
		t.Fatal("an empty offer reads as every device rejected")
	}
	if !everyDeviceRejected([]uint16{0, 92}, map[uint16]bool{0: true, 92: true}) {
		t.Fatal("both devices rejected is not every device")
	}
}

func TestDeviceNumbersAreTheOfferedDevicesOnce(t *testing.T) {
	got := deviceNumbers([]types.JID{calleeDevice(0), calleeDevice(92), calleeDevice(92)})
	if len(got) != 2 || got[0] != 0 || got[1] != 92 {
		t.Fatalf("deviceNumbers = %v, want [0 92]", got)
	}
}
