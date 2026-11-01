package meowcaller

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func ep(name string, fna bool, auth uint32, ip string, port uint16) relayEndpoint {
	return relayEndpoint{
		relayName: name, isFNA: fna, authTokenID: auth,
		addresses: []relayAddress{{ipv4: ip, port: port}},
	}
}

// epToken is ep with a token_id. token_id was observed to be per-call noise,
// so these fixtures exist to prove the selection is INDIFFERENT to it.
func epToken(name string, token uint32, ip string, port uint16) relayEndpoint {
	e := ep(name, false, 0, ip, port)
	e.tokenID = token
	return e
}

// What is NOT testable here: the relay's bridging decision. Nothing in this
// module can observe what a relay does with our packets — there is no vector
// and no fixture, only a live call.
//
// TestTheReportNamesTheBranchThatChose pins the report against every branch of
// selectMediaRelayEndpoint, which is upstream's getMediaRelayEndpoint again:
// the inbound-no-FNA "bind the LAST endpoint" guess (fork patch 3) is gone,
// because the fan-out binds every offered relay and makes the choice of one
// moot. What this selection still decides is the PRIMARY — the relay listed
// first in the fan-out and the only one the group path uses.
func TestTheReportNamesTheBranchThatChose(t *testing.T) {
	fna := ep("gru1c01", true, 0, "1.1.1.1", 3478)
	authed := ep("gru2c02", false, 7, "2.2.2.2", 3479)
	plain := ep("poa1c01", false, 0, "3.3.3.3", 3480)
	// The production shape of both observed calls: two non-FNA endpoints, both
	// auth_token_id=0, carrying opposite token_ids on the same positions.
	tok1 := epToken("gig4c02", 1, "4.4.4.4", 3478)
	tok0 := epToken("gru2c01", 0, "6.6.6.6", 3478)

	cases := []struct {
		name    string
		rd      *relayData
		inbound bool
		branch  string
		chosen  string
		index   int
		fnaN    int
	}{
		{"inbound prefers fna", &relayData{endpoints: []relayEndpoint{authed, fna}}, true, RelayBranchInboundFNA, "gru1c01", 1, 1},
		{"inbound with no fna falls through", &relayData{endpoints: []relayEndpoint{authed, plain}}, true, RelayBranchOutboundAuthed, "gru2c02", 0, 0},
		{"outbound ignores fna", &relayData{endpoints: []relayEndpoint{fna, authed}}, false, RelayBranchOutboundAuthed, "gru2c02", 1, 1},
		{"unauthed non-fna, outbound", &relayData{endpoints: []relayEndpoint{plain}}, false, RelayBranchNonFNA, "poa1c01", 0, 0},
		// Patch 3 is gone: an inbound call with no fna and no authed entry
		// takes the FIRST non-FNA entry again, exactly as upstream does, in
		// both token_id orders.
		{"inbound with no fna takes the FIRST entry", &relayData{endpoints: []relayEndpoint{tok1, tok0}}, true, RelayBranchNonFNA, "gig4c02", 0, 0},
		{"inbound with no fna takes the FIRST entry whatever the token ids", &relayData{endpoints: []relayEndpoint{tok0, tok1}}, true, RelayBranchNonFNA, "gru2c01", 0, 0},
		{"outbound with no fna takes the FIRST entry", &relayData{endpoints: []relayEndpoint{tok1, tok0}}, false, RelayBranchNonFNA, "gig4c02", 0, 0},
		{"only fna, outbound", &relayData{endpoints: []relayEndpoint{fna}}, false, RelayBranchFirst, "gru1c01", 0, 1},
		{"no endpoints", &relayData{}, true, RelayBranchNone, "", -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel := describeRelaySelection("CALLID", tc.rd, tc.inbound, true, nil)
			if sel.Branch != tc.branch {
				t.Fatalf("branch = %q, want %q", sel.Branch, tc.branch)
			}
			if sel.ChosenIndex != tc.index {
				t.Fatalf("chosen index = %d, want %d", sel.ChosenIndex, tc.index)
			}
			if sel.FNACount != tc.fnaN {
				t.Fatalf("fna count = %d, want %d", sel.FNACount, tc.fnaN)
			}
			if len(sel.Endpoints) != len(tc.rd.endpoints) {
				t.Fatalf("reported %d endpoints, offer parsed %d", len(sel.Endpoints), len(tc.rd.endpoints))
			}
			if tc.chosen == "" {
				if sel.Chosen != nil {
					t.Fatalf("chosen = %v, want nil", sel.Chosen)
				}
				return
			}
			if sel.Chosen == nil || sel.Chosen.RelayName != tc.chosen {
				t.Fatalf("chosen = %v, want %q", sel.Chosen, tc.chosen)
			}
			// The report must agree with what the media path actually uses.
			used := getMediaRelayEndpoint(tc.rd, tc.inbound)
			if used == nil || used.relayName != sel.Chosen.RelayName {
				t.Fatalf("report says %q, media path uses %v", sel.Chosen.RelayName, used)
			}
		})
	}
}

// TestTheReportCarriesNoKeyMaterial is the production-safety property. It
// reads the EMITTED FORMS — the JSON the log event and the observer carry, and
// the one-line summary — rather than the struct's fields, because a leak would
// arrive by a field being added, which a field-by-field assertion would miss.
func TestTheReportCarriesNoKeyMaterial(t *testing.T) {
	rd := &relayData{
		relayKeyASCII: []byte("SUPERSECRETRELAYKEY"),
		relayTokens:   [][]byte{[]byte("SECRETTOKENBYTES")},
		endpoints:     []relayEndpoint{ep("gru1c01", true, 0, "1.1.1.1", 3478)},
	}
	sel := describeRelaySelection("CALLID", rd, true, true, []relayBinding{
		{ep: &rd.endpoints[0], err: errors.New("relay connect: dtls handshake: timeout")},
	})
	encoded, err := json.Marshal(sel)
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{string(encoded), sel.Summary()} {
		if form == "" {
			t.Fatal("an emitted form rendered empty")
		}
		for _, secret := range []string{"SUPERSECRETRELAYKEY", "SECRETTOKENBYTES"} {
			if strings.Contains(form, secret) {
				t.Fatalf("emitted form leaked %q: %s", secret, form)
			}
		}
	}
	if !strings.Contains(sel.Summary(), "1.1.1.1") || !strings.Contains(sel.Summary(), "branch=inbound_fna") {
		t.Fatalf("summary is missing the endpoint or the branch: %s", sel.Summary())
	}
}

// TestTheReportListsEveryRelayBound is patch 2 adjusted for the fan-out: the
// report names EVERY relay the call is on and every one that failed, not one
// chosen endpoint — the question is no longer which relay we picked.
func TestTheReportListsEveryRelayBound(t *testing.T) {
	rd := &relayData{endpoints: []relayEndpoint{
		epToken("gig4c02", 0, "4.4.4.4", 3478),
		epToken("gru2c01", 1, "6.6.6.6", 3478),
		epToken("poa1c01", 2, "3.3.3.3", 3478),
	}}
	bindings := []relayBinding{
		{ep: &rd.endpoints[0]},
		{ep: &rd.endpoints[1]},
		{ep: &rd.endpoints[2], err: errors.New("relay connect timed out (DTLS didn't complete)")},
	}
	sel := describeRelaySelection("CALLID", rd, true, true, bindings)

	if !sel.FanOut {
		t.Fatal("a 1:1 report says fan_out=false")
	}
	var bound []string
	for _, b := range sel.Bound {
		bound = append(bound, b.RelayName)
	}
	if strings.Join(bound, ",") != "gig4c02,gru2c01" {
		t.Fatalf("bound = %v, want both relays that came up, primary first", bound)
	}
	if len(sel.Failed) != 1 || sel.Failed[0].Relay.RelayName != "poa1c01" || !strings.Contains(sel.Failed[0].Error, "timed out") {
		t.Fatalf("failed = %+v, want poa1c01 with its reason", sel.Failed)
	}
	for _, want := range []string{"bound=[gig4c02 gru2c01]", "failed=[poa1c01(", "fan_out=true"} {
		if !strings.Contains(sel.Summary(), want) {
			t.Fatalf("summary lacks %q: %s", want, sel.Summary())
		}
	}
}
