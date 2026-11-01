package meowcaller

// Telling a callee's devices that a call we placed is over for them.
//
// An offer rings EVERY device of the callee (placeCall addresses one
// <destination> entry per device GetUserDevices returned). WhatsApp routes
// call signaling per device and does not fan a <terminate> out, so a device
// is only told to stop ringing by a <terminate> addressed to that device.
// Two moments need it:
//
//   - one device ANSWERS or DECLINES: the caller tells the others, with
//     reason accepted_elsewhere / rejected_elsewhere. The callee never does
//     this for its own devices — it is caller-driven.
//   - the caller gives up before anybody answered (our hang-up, which is also
//     how an integrator's ring deadline ends a call): every device the offer
//     rang is told, with no reason.
//
// Before this, the fork sent ONE terminate to the bare peer before a pickup
// and nothing at all to the callee's other devices after one, so a phone kept
// ringing after a Web tab had answered, and the reverse.
//
// The one thing this must never do is end the call it is meant to tidy up: a
// terminate that reaches the ANSWERING device on a live call hangs it up. So
// the answering device is matched on device identity (user, server, device —
// not the whole JID), every device that could be the answerer is excluded,
// and when the answerer cannot be found among the offered devices at all,
// nothing is sent.

import (
	"context"

	"go.mau.fi/whatsmeow/types"

	"github.com/purpshell/meowcaller/signaling"
)

// The <terminate reason> tokens the caller sends a callee's other devices.
// The wire values are WhatsApp's.
const (
	terminateReasonAcceptedElsewhere = "accepted_elsewhere"
	terminateReasonRejectedElsewhere = "rejected_elsewhere"
)

// recordOffer notes the callee devices an offer was addressed to, once as
// device numbers for the reject rule and once as JIDs for the terminates.
func (m *engineCall) recordOffer(devices []types.JID) {
	m.offeredDevices = deviceNumbers(devices)
	m.ringDevices = append([]types.JID(nil), devices...)
}

// takeRingDevices hands back, ONCE, the callee devices a call we placed was
// offered to, and the creator a terminate to them carries. The list is cleared
// so that a duplicate accept, a reject racing a hang-up, or a hang-up after a
// pickup cannot address the same devices again. ok is false for an inbound
// call, a group call, an unknown call, or a list already taken.
//
// Source of truth: https://github.com/oxidezap/whatsapp-rust/blob/0d1373a8f06e0dfa72f3ea1c4c33abae9fd21d61/wacore/src/voip_control/registry.rs#L3263-L3277 (take_dismiss_targets)
func (e *engine) takeRingDevices(callID string) (creator types.JID, devices []types.JID, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.calls[callID]
	if m == nil {
		return types.JID{}, nil, false
	}
	return m.takeRingDevicesLocked()
}

// takeRingDevicesLocked is takeRingDevices for a caller holding e.mu.
func (m *engineCall) takeRingDevicesLocked() (creator types.JID, devices []types.JID, ok bool) {
	if m.direction != CallDirectionOutgoing || m.group || len(m.ringDevices) == 0 {
		return types.JID{}, nil, false
	}
	devices = m.ringDevices
	m.ringDevices = nil
	return m.creator, devices, true
}

// sameDevice compares device identity only. The device list and a stanza's
// from can carry the same physical device with different representation
// details, so whole-JID equality is the wrong test.
//
// Source of truth: https://github.com/oxidezap/whatsapp-rust/blob/0d1373a8f06e0dfa72f3ea1c4c33abae9fd21d61/src/handlers/call.rs#L1804-L1808 (same_device)
func sameDevice(a, b types.JID) bool {
	return a.User == b.User && a.Server == b.Server && a.Device == b.Device
}

// siblingDevices is offered minus every device in deciders. found reports
// whether at least one decider is among the offered devices: when none is,
// the device that answered cannot be told apart from the others.
func siblingDevices(offered []types.JID, deciders ...types.JID) (others []types.JID, found bool) {
	for _, d := range offered {
		decider := false
		for _, x := range deciders {
			if !x.IsEmpty() && sameDevice(d, x) {
				decider = true
				break
			}
		}
		if decider {
			found = true
			continue
		}
		others = append(others, d)
	}
	return others, found
}

// sendDeviceTerminates sends one <terminate> per device, each addressed to
// that device JID with its own stanza id — not one stanza with a
// <destination> block, which WhatsApp only fans out for an offer. It tries
// every device whatever an earlier send did, and returns the first error.
//
// Source of truth: https://github.com/oxidezap/whatsapp-rust/blob/0d1373a8f06e0dfa72f3ea1c4c33abae9fd21d61/src/client/voip.rs#L2130-L2145 (terminate_inner)
func (e *engine) sendDeviceTerminates(callID string, creator types.JID, devices []types.JID, reason string) error {
	var reasonAttr *string
	if reason != "" {
		reasonAttr = &reason
	}
	var first error
	for _, dev := range devices {
		term := signaling.BuildTerminate(&signaling.TerminateParams{
			CallID: callID, To: dev, CallCreator: creator, Reason: reasonAttr,
		})
		term.Attrs["id"] = e.nextCallNodeID()
		err := e.transmitCallNode(context.Background(), term)
		if err != nil && first == nil {
			first = err
		}
		e.logDeviceTerminate(callID, dev, reason, err)
	}
	return first
}

func (e *engine) logDeviceTerminate(callID string, dev types.JID, reason string, err error) {
	if e.c == nil {
		return
	}
	ev := e.c.log.Info()
	if err != nil {
		ev = e.c.log.Warn().Err(err)
	}
	ev.Str("call_id", callID).Str("to", dev.String()).Str("reason", reason).
		Msg("told one of the callee's devices the call is over for it")
	e.c.diag.Emit("meta", map[string]any{
		"event": "device_terminate", "call_id": callID, "to": dev.String(),
		"reason": reason, "sent": err == nil,
	})
}

// dismissAfterAccept tells every offered device except the one that answered
// to stop ringing (accepted_elsewhere). deciders is every JID that may name
// the answering device — the accept's from, and the device the engine settled
// on after it — and all of them are spared: an ambiguous answer leaves a
// device ringing rather than hanging up the live call. When no decider is an
// offered device, nothing is sent at all.
//
// Source of truth: https://github.com/oxidezap/whatsapp-rust/blob/0d1373a8f06e0dfa72f3ea1c4c33abae9fd21d61/src/handlers/call.rs#L1719-L1770 (dismiss_outgoing_siblings)
func (e *engine) dismissAfterAccept(callID string, deciders ...types.JID) {
	creator, offered, ok := e.takeRingDevices(callID)
	if !ok {
		return
	}
	others, found := siblingDevices(offered, deciders...)
	if !found {
		if e.c != nil {
			e.c.log.Warn().Str("call_id", callID).Int("offered", len(offered)).
				Msg("the answering device is not one the offer rang; not dismissing the callee's other devices")
		}
		return
	}
	_ = e.sendDeviceTerminates(callID, creator, others, terminateReasonAcceptedElsewhere)
}

// dismissAfterReject tells every offered device except the one that declined
// that the call is over (rejected_elsewhere). The call is already ended, so a
// decider that cannot be found costs nothing: every offered device is told.
// devices is what takeRingDevicesLocked returned, taken before finishCall
// dropped the call.
//
// Source of truth: https://github.com/oxidezap/whatsapp-rust/blob/0d1373a8f06e0dfa72f3ea1c4c33abae9fd21d61/src/handlers/call.rs#L1719-L1770 (dismiss_outgoing_siblings)
func (e *engine) dismissAfterReject(callID string, creator types.JID, devices []types.JID, rejecter types.JID) {
	others, _ := siblingDevices(devices, rejecter)
	_ = e.sendDeviceTerminates(callID, creator, others, terminateReasonRejectedElsewhere)
}
