package meowcaller

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// The fan-out and the offer filter are upstream PR #26, ported. NOT testable
// here: whether the caller's election then lands on an offered relay, and
// whether that relay forwards the caller's media. There is no relay and no
// peer in this module; a live call is the only test of either.

func relayLatencyEvent(names ...string) *events.CallRelayLatency {
	var tes []waBinary.Node
	for _, name := range names {
		tes = append(tes, waBinary.Node{
			Tag:     "te",
			Attrs:   waBinary.Attrs{"latency": "33554462", "relay_name": name},
			Content: []byte{203, 0, 113, 9, 0x0d, 0x96},
		})
	}
	return &events.CallRelayLatency{
		BasicCallMeta: types.BasicCallMeta{From: peerJID(), CallCreator: creatorJID(), CallID: "CID"},
		Data: &waBinary.Node{Tag: "call", Content: []waBinary.Node{{
			Tag: "relaylatency", Content: tes,
		}}},
	}
}

// answeredRelayNames reads the relay_name of every relaylatency we sent.
func answeredRelayNames(s *sentNodes) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for _, n := range s.nodes {
		for _, child := range n.GetChildren() {
			if child.Tag != "relaylatency" {
				continue
			}
			for _, te := range child.GetChildren() {
				names = append(names, te.AttrGetter().String("relay_name"))
			}
		}
	}
	return names
}

// TestTheLatencyEchoSkipsRelaysOutsideTheOffer is the out-of-offer-relay fix:
// the caller probes its own nearest edge, which is not in our offer; echoing
// it endorses a relay we hold no token for. Offered relays are still answered.
func TestTheLatencyEchoSkipsRelaysOutsideTheOffer(t *testing.T) {
	eng, _, _ := testEngineWithIncomingCall()
	eng.calls["CID"].relay = twoRelayOffer()
	sent := &sentNodes{}
	eng.sendCallNode = sent.send

	eng.onRelayLatency(relayLatencyEvent("gig4c02", "poa1c01", "gru2c01"))

	got := answeredRelayNames(sent)
	sort.Strings(got)
	if strings.Join(got, ",") != "gig4c02,gru2c01" {
		t.Fatalf("answered probes for %v, want exactly the two offered relays [gig4c02 gru2c01]", got)
	}
}

// TestWithNoOfferedRelaysEveryProbeIsAnswered keeps the pre-#26 behaviour for
// a call whose relay names are unknown: refusing every probe would leave the
// caller no election at all.
func TestWithNoOfferedRelaysEveryProbeIsAnswered(t *testing.T) {
	eng, _, _ := testEngineWithIncomingCall()
	sent := &sentNodes{}
	eng.sendCallNode = sent.send

	eng.onRelayLatency(relayLatencyEvent("gig4c02", "poa1c01"))

	if got := answeredRelayNames(sent); len(got) != 2 {
		t.Fatalf("answered %v, want both probes when the offer named no relays", got)
	}
}

// --- every fan-out socket is ours ---------------------------------------

// fakeRelaySocket is the datagram socket our factory hands out. It records
// where every write went and whether it was closed. Reads fail at once by
// default, so a DTLS handshake over it fails fast; block=true makes reads
// wait until Close, like a relay that never answers.
type fakeRelaySocket struct {
	mu      sync.Mutex
	wroteTo []string
	closed  bool
	block   bool
	closeCh chan struct{}
}

func newFakeRelaySocket(block bool) *fakeRelaySocket {
	return &fakeRelaySocket{block: block, closeCh: make(chan struct{})}
}

func (c *fakeRelaySocket) ReadFrom([]byte) (int, net.Addr, error) {
	if c.block {
		<-c.closeCh
	}
	return 0, nil, net.ErrClosed
}

func (c *fakeRelaySocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.wroteTo = append(c.wroteTo, addr.String())
	return len(p), nil
}

func (c *fakeRelaySocket) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.closeCh)
	}
	return nil
}

func (c *fakeRelaySocket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 59999}
}
func (c *fakeRelaySocket) SetDeadline(time.Time) error      { return nil }
func (c *fakeRelaySocket) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeRelaySocket) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeRelaySocket) state() ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.wroteTo...), c.closed
}

// socketFactory is the integrator's WithMediaPacketConn: it records the relay
// each socket was asked for and the socket it handed out.
type socketFactory struct {
	block   bool
	mu      sync.Mutex
	asked   []string
	sockets map[string]*fakeRelaySocket
}

func (f *socketFactory) open(addr *net.UDPAddr) (net.PacketConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, addr.String())
	if f.sockets == nil {
		f.sockets = map[string]*fakeRelaySocket{}
	}
	s := newFakeRelaySocket(f.block)
	f.sockets[addr.String()] = s
	return s, nil
}

func (f *socketFactory) snapshot() ([]string, map[string]*fakeRelaySocket) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]*fakeRelaySocket{}
	for k, v := range f.sockets {
		out[k] = v
	}
	return append([]string(nil), f.asked...), out
}

func threeRelayOffer() *relayData {
	rd := twoRelayOffer()
	rd.relayTokens = append(rd.relayTokens, []byte("token2"))
	rd.endpoints = append(rd.endpoints, relayEndpoint{
		relayName: "poa1c01", tokenID: 2, addresses: []relayAddress{{ipv4: "203.0.113.3", port: 3478}},
	})
	return rd
}

// TestEveryFanOutSocketComesFromOurFactory is the conflict that matters in
// this port. #26 opens ONE SOCKET PER OFFERED RELAY, and every one of them must
// be the integrator's (WithMediaPacketConn), so each leaves through the
// session's sticky egress — not just the first. It proves, for EVERY offered
// relay: the factory was asked for a socket for that relay's address; the DTLS
// handshake actually ran over the socket it returned (bytes were written to
// it, addressed to that relay and no other); and the socket was closed.
func TestEveryFanOutSocketComesFromOurFactory(t *testing.T) {
	f := &socketFactory{}
	c := &Client{mediaPacketConn: f.open}
	eng := newEngine(c)
	rd := threeRelayOffer()

	_, bindings, err := eng.connectAndAllocateAll(context.Background(), rd, [9]uint32{}, true, true)
	if err == nil {
		t.Fatal("the fan-out connected to relays that do not exist; it cannot have used our sockets")
	}
	if len(bindings) != 3 {
		t.Fatalf("the fan-out targeted %d relays, want all 3 offered", len(bindings))
	}

	asked, sockets := f.snapshot()
	want := []string{"203.0.113.1:3478", "203.0.113.2:3478", "203.0.113.3:3478"}
	sort.Strings(asked)
	if strings.Join(asked, ",") != strings.Join(want, ",") {
		t.Fatalf("our factory was asked for sockets %v, want one per offered relay %v — any relay missing here bound its own socket on the host interface", asked, want)
	}
	for _, relayAddr := range want {
		s := sockets[relayAddr]
		wrote, closed := s.state()
		if len(wrote) == 0 {
			t.Errorf("relay %s: nothing was written to the socket our factory gave it; its handshake ran over some other socket", relayAddr)
		}
		for _, to := range wrote {
			if to != relayAddr {
				t.Errorf("relay %s: its socket carried a datagram to %s", relayAddr, to)
			}
		}
		if !closed {
			t.Errorf("relay %s: the socket our factory gave it was not closed after the failed connect", relayAddr)
		}
	}
}

// TestAGroupCallStillBindsOnlyThePrimary: multi=false keeps the single-relay
// semantics for the group path.
func TestAGroupCallStillBindsOnlyThePrimary(t *testing.T) {
	f := &socketFactory{}
	eng := newEngine(&Client{mediaPacketConn: f.open})

	_, _, _ = eng.connectAndAllocateAll(context.Background(), threeRelayOffer(), [9]uint32{}, true, false)

	if asked, _ := f.snapshot(); len(asked) != 1 || asked[0] != "203.0.113.1:3478" {
		t.Fatalf("a single-relay connect asked for sockets %v, want only the primary", asked)
	}
}

// --- the merge and the duplicate filter ----------------------------------

// scriptedRelay is a relayConn that delivers a fixed list of datagrams and
// records what was sent to it.
type scriptedRelay struct {
	mu      sync.Mutex
	inbound [][]byte
	sent    [][]byte
	closed  chan struct{}
	once    sync.Once
}

func newScriptedRelay(inbound ...[]byte) *scriptedRelay {
	return &scriptedRelay{inbound: inbound, closed: make(chan struct{})}
}

func (r *scriptedRelay) Recv(buf []byte) (int, error) {
	r.mu.Lock()
	if len(r.inbound) > 0 {
		pkt := r.inbound[0]
		r.inbound = r.inbound[1:]
		r.mu.Unlock()
		return copy(buf, pkt), nil
	}
	r.mu.Unlock()
	<-r.closed
	return 0, net.ErrClosed
}

func (r *scriptedRelay) Send(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, append([]byte(nil), data...))
	return len(data), nil
}

func (r *scriptedRelay) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

func (r *scriptedRelay) sentPayloads() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, p := range r.sent {
		out = append(out, string(p))
	}
	return out
}

func rtpPacket(ssrc uint32, seq uint16) []byte {
	pkt := make([]byte, 12)
	pkt[0] = 0x80
	pkt[1] = 120
	pkt[2], pkt[3] = byte(seq>>8), byte(seq)
	pkt[8], pkt[9], pkt[10], pkt[11] = byte(ssrc>>24), byte(ssrc>>16), byte(ssrc>>8), byte(ssrc)
	return pkt
}

// TestTheFanOutDropsTheSamePacketArrivingFromTwoRelays: bound everywhere, the
// caller's packet can arrive once per relay. Both copies come out of the merge
// (attributed to the relay they came through), and the replay filter the
// receive loop applies keeps exactly one — a duplicate reaching the playout
// buffer resets it.
func TestTheFanOutDropsTheSamePacketArrivingFromTwoRelays(t *testing.T) {
	a := newScriptedRelay(rtpPacket(0xAABBCCDD, 7), rtpPacket(0xAABBCCDD, 8))
	b := newScriptedRelay(rtpPacket(0xAABBCCDD, 7))
	f := newRelayFanout([]relayConn{a, b}, [][]byte{[]byte("A"), []byte("B")}, []string{"gig4c02", "gru2c01"})
	defer f.Close()

	filter := newRtpReplayFilter()
	fromRelay := map[int]int{}
	kept := 0
	buf := make([]byte, 64)
	for i := 0; i < 3; i++ {
		n, idx, err := f.RecvFrom(buf)
		if err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		fromRelay[idx]++
		seq := uint16(buf[2])<<8 | uint16(buf[3])
		ssrc := uint32(buf[8])<<24 | uint32(buf[9])<<16 | uint32(buf[10])<<8 | uint32(buf[11])
		if n != 12 {
			t.Fatalf("recv %d returned %d bytes", i, n)
		}
		if !filter.Duplicate(ssrc, seq) {
			kept++
		}
	}
	if fromRelay[0] != 2 || fromRelay[1] != 1 {
		t.Fatalf("packets attributed to relays %v, want relay 0 twice and relay 1 once", fromRelay)
	}
	if kept != 2 {
		t.Fatalf("the filter kept %d of 3 datagrams, want 2: seq 7 arrived twice and must pass once", kept)
	}
}

func TestTheReplayFilterIsPerStreamAndForgetsAReusedSlot(t *testing.T) {
	f := newRtpReplayFilter()
	if f.Duplicate(1, 100) {
		t.Fatal("a first packet was called a duplicate")
	}
	if !f.Duplicate(1, 100) {
		t.Fatal("the same (ssrc, seq) twice was not caught")
	}
	if f.Duplicate(2, 100) {
		t.Fatal("the same seq on ANOTHER ssrc was called a duplicate")
	}
	// 1124 lands in the same 1024-slot as 100 and is a different packet.
	if f.Duplicate(1, 1124) {
		t.Fatal("a later packet sharing a ring slot was called a duplicate")
	}
}

// TestBroadcastGoesEverywhereButEachRelayGetsOnlyItsOwnAllocate: media and
// pings go to every relay; an allocate carries one relay's token and is
// meaningless to another, so the refresh never crosses.
func TestBroadcastGoesEverywhereButEachRelayGetsOnlyItsOwnAllocate(t *testing.T) {
	a, b := newScriptedRelay(), newScriptedRelay()
	f := newRelayFanout([]relayConn{a, b}, [][]byte{[]byte("alloc-A"), []byte("alloc-B")}, []string{"a", "b"})
	defer f.Close()

	if _, err := f.Send([]byte("rtp")); err != nil {
		t.Fatal(err)
	}
	if err := f.ResendAllocates(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(a.sentPayloads(), ","); got != "rtp,alloc-A" {
		t.Fatalf("relay A received %q", got)
	}
	if got := strings.Join(b.sentPayloads(), ","); got != "rtp,alloc-B" {
		t.Fatalf("relay B received %q", got)
	}
}

// --- a call nobody answers holds no relay socket -------------------------

func waitClosed(t *testing.T, f *socketFactory, n int) {
	t.Helper()
	waitUntil(t, "every handed-out socket closed", func() bool {
		_, sockets := f.snapshot()
		if len(sockets) < n {
			return false
		}
		for _, s := range sockets {
			if _, closed := s.state(); !closed {
				return false
			}
		}
		return true
	})
}

// TestARingingCallThatEndsReleasesItsRelaySockets: early media opens the
// fan-out at the offer. A caller who hangs up while we are still connecting
// must not leave a socket behind — relay.ConnectRelayMedia takes no context,
// so without relaySocket the abandoned handshake kept its socket until pion's
// own timeout, and a connect that then succeeded was never closed at all.
func TestARingingCallThatEndsReleasesItsRelaySockets(t *testing.T) {
	f := &socketFactory{block: true}
	eng, call, _ := earlyMediaEngine(f.open)

	eng.ringInbound("CID", peerJID(), creatorJID(), false, call)
	waitUntil(t, "both fan-out sockets opened at the offer", func() bool {
		asked, _ := f.snapshot()
		return len(asked) == 2
	})

	eng.onTerminate("CID", "timeout")
	waitClosed(t, f, 2)
}

// TestTheRingLimitReleasesAnUnansweredCallsSockets is the same property when
// the terminate never arrives: past earlyMediaRingLimit the media stops, and
// an Answer that comes after does not reopen it.
func TestTheRingLimitReleasesAnUnansweredCallsSockets(t *testing.T) {
	old := earlyMediaRingLimit
	earlyMediaRingLimit = 100 * time.Millisecond
	t.Cleanup(func() { earlyMediaRingLimit = old })

	f := &socketFactory{block: true}
	eng, call, _ := earlyMediaEngine(f.open)

	eng.ringInbound("CID", peerJID(), creatorJID(), false, call)
	waitClosed(t, f, 2)

	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if asked, _ := f.snapshot(); len(asked) != 2 {
		t.Fatalf("an Answer after the ring limit reopened media: %d sockets asked for, want 2", len(asked))
	}
}

// TestAnAnsweredCallIsNotCutByTheRingLimit: Answer disarms the limit.
func TestAnAnsweredCallIsNotCutByTheRingLimit(t *testing.T) {
	old := earlyMediaRingLimit
	earlyMediaRingLimit = 100 * time.Millisecond
	t.Cleanup(func() { earlyMediaRingLimit = old })

	f := &socketFactory{block: true}
	eng, call, _ := earlyMediaEngine(f.open)
	eng.ringInbound("CID", peerJID(), creatorJID(), false, call)
	if err := eng.answer(call); err != nil {
		t.Fatalf("answer: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	_, sockets := f.snapshot()
	for addr, s := range sockets {
		if _, closed := s.state(); closed {
			t.Fatalf("socket for %s was closed by the ring limit on an ANSWERED call", addr)
		}
	}
	eng.onTerminate("CID", "hangup")
	waitClosed(t, f, 2)
}
