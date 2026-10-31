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

// epToken is ep with the token_id that the #40 fallback now discriminates on.
func epToken(name string, token uint32, ip string, port uint16) relayEndpoint {
	e := ep(name, false, 0, ip, port)
	e.tokenID = token
	return e
}

// TestTheReportNamesTheBranchThatChose pins the report against every branch of
// selectMediaRelayEndpoint, including the #40 case: an inbound call with no
// is_fna endpoint, which now resolves by token_id rather than by offer order.
func TestTheReportNamesTheBranchThatChose(t *testing.T) {
	fna := ep("gru1c01", true, 0, "1.1.1.1", 3478)
	authed := ep("gru2c02", false, 7, "2.2.2.2", 3479)
	plain := ep("poa1c01", false, 0, "3.3.3.3", 3480)
	// The production shape of the 06:33 call: two non-FNA endpoints, both
	// auth_token_id=0, differing only in token_id. gig4c02 came FIRST and was
	// what the old fallback chose.
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
		// The #40 guess, on the offer production actually sent.
		{"inbound with no fna prefers token_id 0", &relayData{endpoints: []relayEndpoint{tok1, tok0}}, true, RelayBranchInboundNoFNAToken0, "gru2c01", 1, 0},
		{"inbound with no fna and no token_id 0 takes the LAST", &relayData{endpoints: []relayEndpoint{tok1, tok2}}, true, RelayBranchInboundNoFNALast, "mia1c01", 1, 0},
		// The scoping, both ways: an inbound call that HAS an authed endpoint
		// is untouched by the guess, and an OUTBOUND call on the exact
		// production offer still takes the first in offer order.
		{"outbound with no fna is unchanged", &relayData{endpoints: []relayEndpoint{tok1, tok0}}, false, RelayBranchNonFNA, "gig4c02", 0, 0},
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
