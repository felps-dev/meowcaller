package meowcaller

// TEMPORARY DIAGNOSTIC — remove once purpshell/meowcaller#40 is understood.
//
// Issue #40 is "no inbound audio when the offer carries no is_fna endpoint",
// reported from Brazil against the poa/gru/mia relays. The relays a call's
// media is bound to are decided over unexported types, so from outside this
// module there is no way to tell which ones a silent call was on. This file
// makes exactly that observable and nothing else: the endpoint list as parsed
// from the offer's <relay> node, the PRIMARY entry and the branch that chose
// it, and — since the fan-out (upstream PR #26) binds every offered relay —
// every relay that was actually bound, and why any other was not.
//
// It carries no key, no token bytes, no call key and no media. Relay
// addresses, ports, token IDs and the is_fna flag are the whole payload,
// because this is meant to run against a live credential in production.

import (
	"fmt"
	"strings"
)

// Relay endpoint selection branches, as named in the report. One constant per
// `return` in selectMediaRelayEndpoint, so a report names a line of code.
const (
	// RelayBranchInboundFNA: the call is inbound and an is_fna="1" endpoint
	// existed, so media was allocated on the caller's own FNA relay. This is
	// the branch that WORKS; #40 is about its absence.
	RelayBranchInboundFNA = "inbound_fna"

	// RelayBranchOutboundAuthed: a non-FNA endpoint with auth_token_id≠0.
	RelayBranchOutboundAuthed = "outbound_authed"

	// RelayBranchNonFNA: a non-FNA endpoint with auth_token_id==0.
	RelayBranchNonFNA = "non_fna"

	// RelayBranchFirst: no non-FNA endpoint at all; the first entry was taken.
	RelayBranchFirst = "first"

	// RelayBranchNone: the offer carried no usable IPv4 endpoint.
	RelayBranchNone = "none"
)

// RelayEndpointInfo is one <te2> endpoint of the offer's <relay> node, with
// the attributes that distinguish the entries from each other. Deliberately
// not the whole relayEndpoint: no token bytes, ever.
type RelayEndpointInfo struct {
	RelayID     uint32 `json:"relay_id"`
	RelayName   string `json:"relay_name"`
	TokenID     uint32 `json:"token_id"`
	AuthTokenID uint32 `json:"auth_token_id"`
	IsFNA       bool   `json:"is_fna"`
	IPv4        string `json:"ipv4"`
	Port        uint16 `json:"port"`
}

// String renders one endpoint compactly, for the one-line log form.
func (i RelayEndpointInfo) String() string {
	return fmt.Sprintf("%s(%s:%d id=%d token=%d auth=%d fna=%t)",
		i.RelayName, i.IPv4, i.Port, i.RelayID, i.TokenID, i.AuthTokenID, i.IsFNA)
}

// RelayBindFailure is one offered relay the fan-out could not bind, and why.
// The error is the connect or allocate failure as text: no key, no token.
type RelayBindFailure struct {
	Relay RelayEndpointInfo `json:"relay"`
	Error string            `json:"error"`
}

// RelayEndpointSelection is the once-per-call diagnostic report, emitted once
// the relays have been dialled.
//
// # One call, every offered relay
//
// A 1:1 call is bound to EVERY offered relay (upstream PR #26): each gets its
// own socket, DataChannel and allocate; outbound media is broadcast to all of
// them and inbound is merged from all of them. Bound lists the relays that
// came up and Failed the ones that did not. Chosen is the PRIMARY — listed
// first in the fan-out and the only relay a group call uses — and Branch names
// the rule that picked it. Which relay the caller's media actually ARRIVED on
// is in the media census (MediaCensus.Relays), not here.
type RelayEndpointSelection struct {
	CallID string `json:"call_id"`

	// Inbound is the direction of the CALL (true = we are the callee).
	Inbound bool `json:"inbound"`

	// Endpoints is the full parsed list, in offer order. IPv6-only entries
	// never reach it: parseRelayData skips any <te2> body that is not six
	// bytes of IPv4:port.
	Endpoints []RelayEndpointInfo `json:"endpoints"`

	// FNACount is how many of them carry is_fna="1". A zero here on an
	// inbound call is the #40 precondition.
	FNACount int `json:"fna_count"`

	// Branch is one of the RelayBranch* constants.
	Branch string `json:"branch"`

	// ChosenIndex indexes Endpoints, or -1 when Branch is RelayBranchNone.
	ChosenIndex int `json:"chosen_index"`

	// Chosen is the primary; nil only when Branch is RelayBranchNone.
	Chosen *RelayEndpointInfo `json:"chosen,omitempty"`

	// FanOut is false for a group call, which binds the primary only.
	FanOut bool `json:"fan_out"`

	// Bound is every relay the call's media is on, primary first.
	Bound []RelayEndpointInfo `json:"bound"`

	// Failed is every relay the fan-out tried and could not bind.
	Failed []RelayBindFailure `json:"failed,omitempty"`
}

// Summary is the one-line human form, used as the log message's detail and
// safe to print anywhere the addresses are.
func (s RelayEndpointSelection) Summary() string {
	parts := make([]string, 0, len(s.Endpoints))
	for _, e := range s.Endpoints {
		parts = append(parts, e.String())
	}
	chosen := "none"
	if s.Chosen != nil {
		chosen = s.Chosen.String()
	}
	bound := make([]string, 0, len(s.Bound))
	for _, b := range s.Bound {
		bound = append(bound, b.RelayName)
	}
	failed := make([]string, 0, len(s.Failed))
	for _, f := range s.Failed {
		failed = append(failed, fmt.Sprintf("%s(%s)", f.Relay.RelayName, f.Error))
	}
	return fmt.Sprintf("inbound=%t fan_out=%t bound=[%s] failed=[%s] branch=%s fna_count=%d chosen=%s endpoints=[%s]",
		s.Inbound, s.FanOut, strings.Join(bound, " "), strings.Join(failed, " "),
		s.Branch, s.FNACount, chosen, strings.Join(parts, " "))
}

// relayEndpointInfo projects one unexported endpoint onto the reportable form.
func relayEndpointInfo(e *relayEndpoint) RelayEndpointInfo {
	info := RelayEndpointInfo{
		RelayID: e.relayID, RelayName: e.relayName,
		TokenID: e.tokenID, AuthTokenID: e.authTokenID, IsFNA: e.isFNA,
	}
	if len(e.addresses) > 0 {
		info.IPv4 = e.addresses[0].ipv4
		info.Port = e.addresses[0].port
	}
	return info
}

// describeRelaySelection re-runs the selection for reporting. It calls the
// same function the media path calls, so the report cannot drift from the
// behaviour: a copied heuristic here would be a second opinion about the one
// thing we are trying to observe.
func describeRelaySelection(callID string, rd *relayData, inbound, fanOut bool, bindings []relayBinding) RelayEndpointSelection {
	sel := RelayEndpointSelection{
		CallID: callID, Inbound: inbound, Branch: RelayBranchNone, ChosenIndex: -1,
		FanOut: fanOut, Bound: []RelayEndpointInfo{},
	}
	for _, b := range bindings {
		if b.ep == nil {
			continue
		}
		info := relayEndpointInfo(b.ep)
		if b.err != nil {
			sel.Failed = append(sel.Failed, RelayBindFailure{Relay: info, Error: b.err.Error()})
			continue
		}
		sel.Bound = append(sel.Bound, info)
	}
	if rd == nil {
		return sel
	}
	for i := range rd.endpoints {
		sel.Endpoints = append(sel.Endpoints, relayEndpointInfo(&rd.endpoints[i]))
		if rd.endpoints[i].isFNA {
			sel.FNACount++
		}
	}
	chosen, branch := selectMediaRelayEndpoint(rd, inbound)
	sel.Branch = branch
	if chosen == nil {
		return sel
	}
	for i := range rd.endpoints {
		if &rd.endpoints[i] == chosen {
			sel.ChosenIndex = i
			break
		}
	}
	info := relayEndpointInfo(chosen)
	sel.Chosen = &info
	return sel
}

// reportRelaySelection emits the report once per call, through the library's
// own logger and to the integrator's observer if one was installed.
func (e *engine) reportRelaySelection(callID string, rd *relayData, inbound, fanOut bool, bindings []relayBinding) {
	sel := describeRelaySelection(callID, rd, inbound, fanOut, bindings)
	e.c.log.Info().
		Str("call_id", sel.CallID).
		Bool("inbound", sel.Inbound).
		Bool("fan_out", sel.FanOut).
		Interface("bound", sel.Bound).
		Interface("failed", sel.Failed).
		Str("branch", sel.Branch).
		Int("fna_count", sel.FNACount).
		Int("endpoint_count", len(sel.Endpoints)).
		Int("chosen_index", sel.ChosenIndex).
		Interface("endpoints", sel.Endpoints).
		Interface("chosen", sel.Chosen).
		Msg("relay endpoint selection (temporary diagnostic, upstream issue #40)")
	e.c.diag.Emit("relay", map[string]any{
		"event": "endpoint_selection", "call_id": sel.CallID, "inbound": sel.Inbound,
		"branch": sel.Branch, "fna_count": sel.FNACount,
		"chosen_index": sel.ChosenIndex, "endpoints": sel.Endpoints, "chosen": sel.Chosen,
		"fan_out": sel.FanOut, "bound": sel.Bound, "failed": sel.Failed,
	})
	if fn := e.c.relayEndpointObserver; fn != nil {
		fn(sel)
	}
}
