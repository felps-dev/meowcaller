package meowcaller

import (
	"encoding/json"
	"strings"
	"testing"
)

func ep(name string, fna bool, auth uint32, ip string, port uint16) relayEndpoint {
	return relayEndpoint{
		relayName: name, isFNA: fna, authTokenID: auth,
		addresses: []relayAddress{{ipv4: ip, port: port}},
	}
}

// epToken is ep with a token_id. The #40 fallback deliberately does NOT read
// it — token_id was observed to be per-call noise — so these fixtures exist to
// prove the selection is INDIFFERENT to it.
func epToken(name string, token uint32, ip string, port uint16) relayEndpoint {
	e := ep(name, false, 0, ip, port)
	e.tokenID = token
	return e
}

// What is NOT testable here: the relay's bridging decision. Nothing in this
// module can observe what a relay does with our packets — there is no vector
// and no fixture, only a live call. These cases pin WHICH endpoint the
// selection binds, which is the whole of what the #40 guess changes; whether
// binding it makes audio flow is answered by placing a call and by nothing
// else.
//
// TestTheReportNamesTheBranchThatChose pins the report against every branch of
// selectMediaRelayEndpoint, including the #40 case: an inbound call with no
// is_fna endpoint, which now resolves to the LAST non-FNA entry in offer
// order, whatever the token_ids are.
func TestTheReportNamesTheBranchThatChose(t *testing.T) {
	fna := ep("gru1c01", true, 0, "1.1.1.1", 3478)
	authed := ep("gru2c02", false, 7, "2.2.2.2", 3479)
	plain := ep("poa1c01", false, 0, "3.3.3.3", 3480)
	// The production shape of both observed calls: two non-FNA endpoints, both
	// auth_token_id=0, a 'gig' relay at index 0 and a 'gru' one at index 1.
	// The two calls carried OPPOSITE token_ids on those same positions, which
	// is why the fixtures come in both orders.
	tok1 := epToken("gig4c02", 1, "4.4.4.4", 3478)
	tok2 := epToken("mia1c01", 2, "5.5.5.5", 3478)
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
		// The #40 guess, on the two offers production actually sent. Same
		// positions, opposite token_ids, same answer: the LAST entry.
		{"inbound with no fna takes the LAST entry", &relayData{endpoints: []relayEndpoint{tok1, tok0}}, true, RelayBranchInboundNoFNALast, "gru2c01", 1, 0},
		{"inbound with no fna takes the LAST entry whatever the token ids", &relayData{endpoints: []relayEndpoint{tok0, tok1}}, true, RelayBranchInboundNoFNALast, "gig4c02", 1, 0},
		{"inbound with no fna ignores a token_id 0 that is not last", &relayData{endpoints: []relayEndpoint{tok0, tok2}}, true, RelayBranchInboundNoFNALast, "mia1c01", 1, 0},
		// Three entries: the guess is the LAST, not the second.
		{"inbound with no fna takes the last of three", &relayData{endpoints: []relayEndpoint{tok1, tok0, tok2}}, true, RelayBranchInboundNoFNALast, "mia1c01", 2, 0},
		// An FNA entry LAST in offer order must not be taken by the fallback:
		// the inbound-FNA branch above claims the call first.
		{"inbound with an fna last still prefers the fna", &relayData{endpoints: []relayEndpoint{tok1, fna}}, true, RelayBranchInboundFNA, "gru1c01", 1, 1},
		// And an inbound call that carries an AUTHED endpoint is untouched by
		// the guess even though an unauthed non-FNA entry sits after it.
		{"inbound with an authed endpoint is unchanged", &relayData{endpoints: []relayEndpoint{authed, tok0}}, true, RelayBranchOutboundAuthed, "gru2c02", 0, 0},
		// The scoping: an OUTBOUND call on the exact production offer still
		// takes the FIRST non-FNA entry in offer order, both orders of
		// token_id, so the guess cannot have moved it.
		{"outbound with no fna is unchanged", &relayData{endpoints: []relayEndpoint{tok1, tok0}}, false, RelayBranchNonFNA, "gig4c02", 0, 0},
		{"outbound with no fna is unchanged, token ids swapped", &relayData{endpoints: []relayEndpoint{tok0, tok1}}, false, RelayBranchNonFNA, "gru2c01", 0, 0},
		{"only fna, outbound", &relayData{endpoints: []relayEndpoint{fna}}, false, RelayBranchFirst, "gru1c01", 0, 1},
		{"no endpoints", &relayData{}, true, RelayBranchNone, "", -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel := describeRelaySelection("CALLID", tc.rd, tc.inbound)
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
	sel := describeRelaySelection("CALLID", rd, true)
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
