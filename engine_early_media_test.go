package meowcaller

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
)

// Early media is upstream PR #43, ported. What these tests CANNOT say is
// whether a relay then forwards the caller's media: there is no relay, no peer
// and no vector here, only a live call answers that. They pin the engine's
// half: when media starts, what Answer does with what arrived before it, and
// that OnReady fires once in either order.

func testEngineWithIncomingCall() (*engine, *Call, *int) {
	c := &Client{}
	c.eng = newEngine(c)
	call := &Call{eng: c.eng, id: "CID", peer: peerJID(), phase: CallPhaseRinging}
	ready := 0
	call.OnReady(func() { ready++ })
	c.eng.calls["CID"] = &engineCall{
		call:      call,
		direction: CallDirectionIncoming,
		from:      peerJID(),
		creator:   creatorJID(),
	}
	return c.eng, call, &ready
}

// sentNodes records every stanza the engine transmits.
type sentNodes struct {
	mu    sync.Mutex
	nodes []waBinary.Node
}

func (s *sentNodes) send(_ context.Context, node waBinary.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = append(s.nodes, node)
	return nil
}

func (s *sentNodes) tags() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.nodes {
		if kids := n.GetChildren(); len(kids) > 0 {
			out = append(out, kids[0].Tag)
		} else {
			out = append(out, n.Tag)
		}
	}
	return out
}

func (s *sentNodes) count(tag string) int {
	n := 0
	for _, t := range s.tags() {
		if t == tag {
			n++
		}
	}
	return n
}

func muteV2Node() *waBinary.Node {
	return &waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"from": peerJID(), "id": "N1"},
		Content: []waBinary.Node{{Tag: "mute_v2", Attrs: waBinary.Attrs{
			"call-id": "CID", "call-creator": creatorJID(), "mute-state": "0",
		}}},
	}
}

func TestFirstInboundRTPWhileRingingWaitsForAnswer(t *testing.T) {
	eng, call, ready := testEngineWithIncomingCall()

	eng.onFirstInboundRTP("CID", call)
	if call.State() != CallPhaseRinging || *ready != 0 {
		t.Fatalf("before answer: phase=%v ready=%d, want ringing and not ready", call.State(), *ready)
	}

	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if call.State() != CallPhaseActive || *ready != 1 {
		t.Fatalf("after answer: phase=%v ready=%d, want active and ready once", call.State(), *ready)
	}
}

func TestFirstInboundRTPAfterAnswerActivates(t *testing.T) {
	eng, call, ready := testEngineWithIncomingCall()

	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if call.State() != CallPhaseConnecting || *ready != 0 {
		t.Fatalf("after answer: phase=%v ready=%d, want connecting", call.State(), *ready)
	}

	eng.onFirstInboundRTP("CID", call)
	if call.State() != CallPhaseActive || *ready != 1 {
		t.Fatalf("after first RTP: phase=%v ready=%d, want active and ready once", call.State(), *ready)
	}
}

// TestAnEarlyMuteV2IsHeldUntilAnswer: the caller's first mute_v2 can arrive
// while we still ring. It must NOT accept then — nobody has answered — and
// Answer must send the <accept> from it, exactly once, because no second
// mute_v2 is coming to trigger it.
func TestAnEarlyMuteV2IsHeldUntilAnswer(t *testing.T) {
	eng, call, _ := testEngineWithIncomingCall()
	sent := &sentNodes{}
	eng.sendCallNode = sent.send

	if handled := eng.onCallRaw(muteV2Node()); handled {
		t.Fatal("mute_v2 while ringing should not be consumed")
	}
	m := eng.calls[call.ID()]
	if !m.earlyMuteSeen || m.earlyMuteFrom != peerJID() || m.earlyMuteCreator != creatorJID() {
		t.Fatalf("early mute not recorded: seen=%v from=%s creator=%s", m.earlyMuteSeen, m.earlyMuteFrom, m.earlyMuteCreator)
	}
	if call.State() != CallPhaseRinging {
		t.Fatalf("phase = %v, want ringing", call.State())
	}
	if n := sent.count("accept"); n != 0 {
		t.Fatalf("an <accept> went out while the call was still ringing (%d sent)", n)
	}

	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if n := sent.count("accept"); n != 1 {
		t.Fatalf("answer sent %d <accept> stanzas for the held mute_v2, want exactly 1 (stanzas: %v)", n, sent.tags())
	}

	// A later mute_v2 is an in-call mute change and must not re-accept.
	eng.onCallRaw(muteV2Node())
	if n := sent.count("accept"); n != 1 {
		t.Fatalf("a post-answer mute_v2 re-sent the accept (%d total)", n)
	}
}

// TestWithoutAnEarlyMuteTheAcceptStillWaitsForMuteV2 is the other order: no
// mute_v2 before Answer, so Answer sends nothing and the first mute_v2 after
// it accepts — the pre-#43 path, unchanged.
func TestWithoutAnEarlyMuteTheAcceptStillWaitsForMuteV2(t *testing.T) {
	eng, call, _ := testEngineWithIncomingCall()
	sent := &sentNodes{}
	eng.sendCallNode = sent.send

	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if n := sent.count("accept"); n != 0 {
		t.Fatalf("answer sent an <accept> with no mute_v2 seen (%d)", n)
	}
	eng.onCallRaw(muteV2Node())
	if n := sent.count("accept"); n != 1 {
		t.Fatalf("the first mute_v2 after answer sent %d accepts, want 1", n)
	}
}

// earlyMediaEngine is an inbound call with everything media needs — call
// key, relay data with two endpoints — and a media socket factory that
// records every relay address it is asked for. The factory refuses, so the
// media loop stops at the first socket; the request is the observable.
type socketRequests struct {
	mu    sync.Mutex
	addrs []string
}

func (r *socketRequests) factory(addr *net.UDPAddr) (net.PacketConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs = append(r.addrs, addr.String())
	return nil, errors.New("no network in this test")
}

func (r *socketRequests) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

func twoRelayOffer() *relayData {
	return &relayData{
		relayKeyASCII: []byte("relaykey"),
		relayTokens:   [][]byte{[]byte("token0"), []byte("token1")},
		endpoints: []relayEndpoint{
			{relayName: "gig4c02", tokenID: 0, addresses: []relayAddress{{ipv4: "203.0.113.1", port: 3478}}},
			{relayName: "gru2c01", tokenID: 1, addresses: []relayAddress{{ipv4: "203.0.113.2", port: 3478}}},
		},
	}
}

func earlyMediaEngine(factory func(*net.UDPAddr) (net.PacketConn, error)) (*engine, *Call, *sentNodes) {
	c := &Client{mediaPacketConn: factory}
	c.eng = newEngine(c)
	sent := &sentNodes{}
	c.eng.sendCallNode = sent.send
	call := &Call{eng: c.eng, id: "CID", peer: peerJID(), phase: CallPhaseRinging}
	c.eng.calls["CID"] = &engineCall{
		call:      call,
		callKey:   iota32(),
		relay:     twoRelayOffer(),
		selfLID:   "111111111111111@lid",
		peerLID:   peerJID().String(),
		direction: CallDirectionIncoming,
		from:      peerJID(),
		creator:   creatorJID(),
	}
	return c.eng, call, sent
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestEarlyMediaStartsAtTheOffer is the #43 change itself: ringing an inbound
// call starts its media — a relay socket is asked for — with no Answer, and
// the call stays ringing.
func TestEarlyMediaStartsAtTheOffer(t *testing.T) {
	req := &socketRequests{}
	eng, call, sent := earlyMediaEngine(req.factory)

	eng.ringInbound("CID", peerJID(), creatorJID(), false, call)

	waitUntil(t, "a relay socket requested at the offer", func() bool { return len(req.snapshot()) > 0 })
	eng.mu.Lock()
	started, answered := eng.calls["CID"].started, eng.calls["CID"].answered
	eng.mu.Unlock()
	if !started || answered {
		t.Fatalf("started=%t answered=%t, want media started on an unanswered call", started, answered)
	}
	if call.State() != CallPhaseRinging {
		t.Fatalf("phase = %v, want ringing: early media must not move the call on", call.State())
	}
	if n := sent.count("preaccept"); n != 1 {
		t.Fatalf("%d preaccepts sent, want 1", n)
	}
}

// TestADeclinedCallHasNoEarlyMedia: an integrator that will not take a call
// says so from its listener, and no relay socket is opened until Answer.
func TestADeclinedCallHasNoEarlyMedia(t *testing.T) {
	req := &socketRequests{}
	eng, call, _ := earlyMediaEngine(req.factory)
	eng.c.OnIncomingCall(func(c *Call) { c.DeclineEarlyMedia() })

	eng.ringInbound("CID", peerJID(), creatorJID(), false, call)
	time.Sleep(50 * time.Millisecond)
	if got := req.snapshot(); len(got) != 0 {
		t.Fatalf("a declined call asked for relay sockets %v before Answer", got)
	}

	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	waitUntil(t, "media started by Answer", func() bool { return len(req.snapshot()) > 0 })
}
