package meowcaller

// Rejects in multi-device WhatsApp (upstream issues #25 and PR #47).
//
// An offer is addressed to EVERY device of the callee (placeCall's
// GetUserDevices fan-out), and every one of them may answer it with a
// <reject> of its own. A companion that cannot or will not take the call —
// a Web tab, a Desktop app, a hosted Business companion, a bot on the same
// number — rejects within half a second while the phone goes on ringing, and
// WhatsApp keeps the call alive for it. Ending the call on the first reject
// from ANY device therefore killed every outbound call to anybody with such a
// companion, before their phone had finished its first ring.
//
// Nothing on the stanza separates the two kinds:
//
//   - count is not a discriminator. WA Web sends count="0" on every reject it
//     makes (whatsapp-rust wacore/src/stanza/call.rs, build_reject) and so
//     does whatsmeow's RejectCall, so a deliberate decline and an automated
//     one are byte-identical there.
//   - reason is only a PARTIAL one. "busy" and "enc" speak for one device
//     (whatsapp-rust REJECT_REASON_BUSY/ENC, which keeps the call ringing on
//     them); the companion reject that killed our calls carried no reason at
//     all, which is also what a person tapping Decline sends.
//
// So the rule is about WHICH device spoke, with the reason as a secondary
// signal (decideReject). The bounds that end a call nobody answers are
// unchanged and are what stop an ignored reject from leaving a call ringing
// forever: the caller's own <terminate>, Hangup (which the integrator's ring
// deadline calls), and the server's error ack.

import (
	"strings"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// Reject reasons a device sends about ITSELF: it is in another call, or it
// could not decrypt the offer. Neither is the callee deciding anything, so the
// callee's other devices keep ringing. The wire tokens are WhatsApp's.
const (
	rejectReasonBusy = "busy"
	rejectReasonEnc  = "enc"
)

// The rule a reject was decided by, as CallRejectReport.Rule carries it.
const (
	// RejectRuleInbound: a reject on a call we RECEIVED comes from another
	// device of this account declining for itself (seen live with
	// reason="unavailable", and from Meta-hosted companions on every call).
	// Ignored; the caller's <terminate> ends the call (upstream PR #47).
	RejectRuleInbound = "inbound_other_device"
	// RejectRuleAnswered: the callee already accepted, so one of their
	// devices declining afterwards changes nothing. Ignored; a <terminate>
	// ends an answered call.
	RejectRuleAnswered = "already_answered"
	// RejectRuleDeviceBusy: reason busy or enc, which speak for one device.
	// Ignored unless it was the last device left.
	RejectRuleDeviceBusy = "device_busy"
	// RejectRuleCompanion: a companion that never rang — it did not
	// preaccept — rejected without a per-device reason. Ignored: that is the
	// automated reject issue #25 describes.
	RejectRuleCompanion = "companion_not_ringing"
	// RejectRulePrimary: the callee's primary device (device 0, the phone)
	// declined. Ends the call.
	RejectRulePrimary = "primary_device"
	// RejectRuleRangDevice: a device that preaccepted — so it rang, and a
	// person saw it — declined. Ends the call.
	RejectRuleRangDevice = "preaccepted_device"
	// RejectRuleAllDevices: every device the offer was addressed to has now
	// rejected, so nothing is left ringing. Ends the call.
	RejectRuleAllDevices = "every_device_rejected"
	// RejectRuleGroup: an outgoing group call keeps its previous behaviour.
	RejectRuleGroup = "group"
)

// CallRejectReport is one <reject> this engine received and what it decided.
// It carries the rejecting device and the stanza's own attributes so that a
// call that ended, or did not, on a reject can be explained from a log line.
type CallRejectReport struct {
	CallID string
	// From is the rejecting device's JID as the stanza carried it.
	From string
	// Device is From's device number; 0 is the account's primary device.
	Device uint16
	// Count and Reason are the <reject>'s attributes, verbatim; "" when
	// absent.
	Count  string
	Reason string
	// Outgoing reports a call this client placed.
	Outgoing bool
	// Final reports that this reject ended the call.
	Final bool
	// Rule is the RejectRule* the decision was made by.
	Rule string
}

// WithCallRejectObserver installs a callback for every <reject> the engine
// receives, ignored or final. fn runs on whatsmeow's event goroutine and must
// not block.
func WithCallRejectObserver(fn func(CallRejectReport)) Option {
	return func(c *config) { c.callRejectObserver = fn }
}

// rejectView is what decideReject needs to know about one call when one of
// the callee's devices rejects it.
type rejectView struct {
	direction    CallDirection
	group        bool
	peerAccepted bool
	device       uint16
	reason       string
	// preAccepted is the devices that preaccepted (rang); offered the
	// devices the offer was addressed to; rejected every device that has
	// rejected so far, this one included.
	preAccepted map[uint16]bool
	offered     []uint16
	rejected    map[uint16]bool
}

// decideReject reports whether a reject ends the call, and by which rule.
//
// For an outgoing 1:1 call it ends only on the primary device, on a device
// that rang, or once no device is left ringing — never on a companion that
// declined for itself while the phone may still be ringing.
func decideReject(v rejectView) (final bool, rule string) {
	switch {
	case v.direction == CallDirectionIncoming:
		return false, RejectRuleInbound
	case v.group:
		return true, RejectRuleGroup
	case v.peerAccepted:
		return false, RejectRuleAnswered
	case everyDeviceRejected(v.offered, v.rejected):
		return true, RejectRuleAllDevices
	case v.reason == rejectReasonBusy || v.reason == rejectReasonEnc:
		return false, RejectRuleDeviceBusy
	case v.device == 0:
		return true, RejectRulePrimary
	case v.preAccepted[v.device]:
		return true, RejectRuleRangDevice
	default:
		return false, RejectRuleCompanion
	}
}

// everyDeviceRejected reports whether every offered device has rejected. An
// unknown offer (no devices recorded) is never "every device": it would make
// the first reject of all final, which is the bug.
func everyDeviceRejected(offered []uint16, rejected map[uint16]bool) bool {
	if len(offered) == 0 {
		return false
	}
	for _, d := range offered {
		if !rejected[d] {
			return false
		}
	}
	return true
}

// deviceNumbers is the device numbers of an offer's destination JIDs, in
// order, once each.
func deviceNumbers(devices []types.JID) []uint16 {
	out := make([]uint16, 0, len(devices))
	seen := map[uint16]bool{}
	for _, d := range devices {
		if !seen[d.Device] {
			seen[d.Device] = true
			out = append(out, d.Device)
		}
	}
	return out
}

// rejectAttrs reads count and reason off a <reject> node, "" when absent.
func rejectAttrs(node *waBinary.Node) (count, reason string) {
	if node == nil {
		return "", ""
	}
	ag := node.AttrGetter()
	return strings.TrimSpace(ag.OptionalString("count")), strings.TrimSpace(ag.OptionalString("reason"))
}

// onReject records one device's reject and ends the call only when
// decideReject says the callee — not one of their devices — declined.
func (e *engine) onReject(ev *events.CallReject) {
	m := e.lookup(ev.CallID)
	if m == nil {
		return
	}
	// Read before taking e.mu: Call.mu is never taken under it elsewhere.
	peerAccepted := m.call != nil && m.call.hasPeerAccepted()
	count, reason := rejectAttrs(ev.Data)
	device := ev.From.Device

	e.mu.Lock()
	m = e.calls[ev.CallID]
	if m == nil {
		e.mu.Unlock()
		return
	}
	if m.rejectedDevices == nil {
		m.rejectedDevices = map[uint16]bool{}
	}
	m.rejectedDevices[device] = true
	final, rule := decideReject(rejectView{
		direction:    m.direction,
		group:        m.group,
		peerAccepted: peerAccepted,
		device:       device,
		reason:       reason,
		preAccepted:  m.preAcceptedDevices,
		offered:      m.offeredDevices,
		rejected:     m.rejectedDevices,
	})
	outgoing := m.direction == CallDirectionOutgoing
	trace := m.trace
	// A final reject on a call we placed leaves the callee's other devices
	// ringing; they are owed a terminate, and the list must be taken before
	// finishCall drops the call.
	var ringCreator types.JID
	var ringDevices []types.JID
	if final {
		ringCreator, ringDevices, _ = m.takeRingDevicesLocked()
	}
	e.mu.Unlock()

	report := CallRejectReport{
		CallID: ev.CallID, From: ev.From.String(), Device: device,
		Count: count, Reason: reason, Outgoing: outgoing, Final: final, Rule: rule,
	}
	trace.reject(report)
	msg := "ignoring reject from one of the peer's devices; the call goes on"
	if final {
		msg = "peer rejected call"
	}
	e.c.log.Info().
		Str("call_id", ev.CallID).
		Str("from", report.From).
		Uint16("device", device).
		Str("count", count).
		Str("reason", reason).
		Bool("final", final).
		Str("rule", rule).
		Msg(msg)
	e.c.diag.Emit("meta", map[string]any{
		"event": "peer_reject", "call_id": ev.CallID, "from": report.From,
		"device": device, "count": count, "reason": reason, "final": final, "rule": rule,
	})
	if fn := e.c.callRejectObserver; fn != nil {
		fn(report)
	}
	if final {
		e.finishCall(ev.CallID, "rejected")
		if len(ringDevices) > 0 {
			e.dismissAfterReject(ev.CallID, ringCreator, ringDevices, ev.From)
		}
	}
}

// recordPreAccept notes that one of the callee's devices preaccepted, i.e.
// rang. Its later reject is a person declining on it.
func (e *engine) recordPreAccept(callID string, from types.JID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.calls[callID]
	if m == nil {
		return
	}
	if m.preAcceptedDevices == nil {
		m.preAcceptedDevices = map[uint16]bool{}
	}
	m.preAcceptedDevices[from.Device] = true
}
