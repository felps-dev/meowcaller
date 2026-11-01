package meowcaller

import (
	"errors"
	"net"
	"sync"

	"github.com/purpshell/meowcaller/relay"
)

// Ported from upstream PR #26 ("Bind every offered relay so phone callers
// don't go deaf after accept"), unmerged upstream. The fork's differences are
// marked where they occur: per-relay inbound attribution (RecvFrom), a
// channel interface so the merge is testable, and relaySocket, which keeps
// every fan-out socket on the integrator's WithMediaPacketConn factory and
// closes it when its connect is abandoned.

// relayConn is the slice of *relay.RelayMediaChannel the fan-out uses.
type relayConn interface {
	Send(data []byte) (int, error)
	Recv(buf []byte) (int, error)
	Close() error
}

var _ relayConn = (*relay.RelayMediaChannel)(nil)

// relayFanout runs one logical media channel across every usable relay in the
// offer, mirroring the reference implementation's bind-to-all model: outbound
// packets broadcast to every relay, inbound merges from all of them.
//
// Phones run client-side relay election shortly after accept and move their
// media to whichever offered relay they measured closest — which is frequently
// not the first one listed. A callee bound to a single relay goes deaf at that
// moment (observed live as 5–8 comfort-noise packets then permanent silence;
// upstream issues #21 and #22). Being connected everywhere makes the election
// outcome irrelevant, PROVIDED the election lands on an offered relay — which
// is what onRelayLatency's offer filter is for.
type relayFanout struct {
	chans  []relayConn
	allocs [][]byte
	names  []string

	packets   chan fanoutPacket
	done      chan struct{}
	closeOnce sync.Once

	mu     sync.Mutex
	closed bool
	live   int
}

// fanoutPacket is one inbound datagram and the index of the relay it came
// through. The index is the fork's addition: the census counts per relay, so a
// call's log says which relay the caller's media actually arrived on.
type fanoutPacket struct {
	data  []byte
	relay int
}

// fanoutBacklog bounds merged inbound packets awaiting Recv. At 60ms audio
// cadence even a multi-relay burst sits far below this; overflow drops rather
// than blocks so one slow consumer can't stall the per-relay readers.
const fanoutBacklog = 256

var errFanoutClosed = errors.New("meowcaller: relay fanout closed")

// newRelayFanout takes ownership of the channels and their matching per-relay
// allocate payloads, and starts one reader per channel.
func newRelayFanout(chans []relayConn, allocs [][]byte, names []string) *relayFanout {
	// Source of truth: https://github.com/JotaDev66/WaCalls/blob/edeb31f0427aba896639db503153b777a405eccf/internal/voip/transport/sctprelay.go#L105-L127
	f := &relayFanout{
		chans:   chans,
		allocs:  allocs,
		names:   names,
		packets: make(chan fanoutPacket, fanoutBacklog),
		done:    make(chan struct{}),
		live:    len(chans),
	}
	for i, ch := range chans {
		go f.readLoop(i, ch)
	}
	return f
}

func (f *relayFanout) readLoop(index int, ch relayConn) {
	buf := make([]byte, 2048)
	for {
		n, err := ch.Recv(buf)
		if err != nil {
			f.readerExited()
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case f.packets <- fanoutPacket{data: pkt, relay: index}:
		case <-f.done:
			return
		default:
			// Backlog full. Live media prefers a dropped packet over a stalled
			// reader; audio recovers next frame, video on the next keyframe.
		}
	}
}

// readerExited closes the fanout once the last relay connection dies, so Recv
// unblocks with an error instead of waiting on relays that are all gone.
func (f *relayFanout) readerExited() {
	f.mu.Lock()
	f.live--
	last := f.live == 0
	f.mu.Unlock()
	if last {
		f.Close()
	}
}

// Send broadcasts one packet to every relay, succeeding if at least one relay
// accepted it. The peer reads our stream from whichever relay it elected, and
// the others simply discard.
func (f *relayFanout) Send(data []byte) (int, error) {
	// Source of truth: https://github.com/JotaDev66/WaCalls/blob/edeb31f0427aba896639db503153b777a405eccf/internal/voip/transport/sctprelay.go#L345-L355
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return 0, errFanoutClosed
	}
	chans := f.chans
	f.mu.Unlock()

	sent := false
	var lastErr error
	for _, ch := range chans {
		if _, err := ch.Send(data); err != nil {
			lastErr = err
			continue
		}
		sent = true
	}
	if !sent {
		if lastErr == nil {
			lastErr = errFanoutClosed
		}
		return 0, lastErr
	}
	return len(data), nil
}

// Recv pops the next packet from any relay into buf, blocking like the
// single-channel Recv it replaces.
func (f *relayFanout) Recv(buf []byte) (int, error) {
	n, _, err := f.RecvFrom(buf)
	return n, err
}

// RecvFrom is Recv plus the index (into names) of the relay the packet came
// through.
func (f *relayFanout) RecvFrom(buf []byte) (int, int, error) {
	select {
	case pkt := <-f.packets:
		return copy(buf, pkt.data), pkt.relay, nil
	case <-f.done:
		// Drain anything already merged before reporting closure.
		select {
		case pkt := <-f.packets:
			return copy(buf, pkt.data), pkt.relay, nil
		default:
			return 0, -1, errFanoutClosed
		}
	}
}

// ResendAllocates re-sends each relay its own allocate payload. Allocates embed
// the relay-specific token and XOR-encoded endpoint, so they must never be
// broadcast: relay A's allocate is meaningless to relay B.
func (f *relayFanout) ResendAllocates() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return errFanoutClosed
	}
	chans, allocs := f.chans, f.allocs
	f.mu.Unlock()

	sent := false
	var lastErr error
	for i, ch := range chans {
		if i >= len(allocs) || allocs[i] == nil {
			continue
		}
		if _, err := ch.Send(allocs[i]); err != nil {
			lastErr = err
			continue
		}
		sent = true
	}
	if !sent && lastErr != nil {
		return lastErr
	}
	return nil
}

// PrimarySend writes to the first relay only. The experimental group-call path
// keeps its original single-relay semantics; only 1:1 calls fan out.
func (f *relayFanout) PrimarySend(data []byte) (int, error) {
	f.mu.Lock()
	if f.closed || len(f.chans) == 0 {
		f.mu.Unlock()
		return 0, errFanoutClosed
	}
	primary := f.chans[0]
	f.mu.Unlock()
	return primary.Send(data)
}

func (f *relayFanout) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		chans := f.chans
		f.mu.Unlock()
		close(f.done)
		for _, ch := range chans {
			_ = ch.Close()
		}
	})
	return nil
}

// rtpReplayFilter drops RTP packets already seen on (ssrc, seq). With every
// relay bridging the same session, one packet can arrive once per relay;
// duplicates reaching the playout buffer read as a zero-timestamp delta, which
// resets it and audibly glitches the stream. A 1024-slot ring per SSRC covers
// ~61s of 60ms audio frames — far beyond any realistic reorder window.
type rtpReplayFilter struct {
	streams map[uint32]*replayRing
}

type replayRing struct {
	seen   [1024 / 64]uint64
	seq    [1024]uint16
	primed bool
}

func newRtpReplayFilter() *rtpReplayFilter {
	return &rtpReplayFilter{streams: make(map[uint32]*replayRing)}
}

// Duplicate records (ssrc, seq) and reports whether it was already seen.
func (r *rtpReplayFilter) Duplicate(ssrc uint32, seq uint16) bool {
	ring, ok := r.streams[ssrc]
	if !ok {
		ring = &replayRing{}
		r.streams[ssrc] = ring
	}
	slot := int(seq) % 1024
	word, bit := slot/64, uint(slot%64)
	if ring.primed && ring.seen[word]&(1<<bit) != 0 && ring.seq[slot] == seq {
		return true
	}
	ring.primed = true
	ring.seen[word] |= 1 << bit
	ring.seq[slot] = seq
	return false
}

// relaySocket opens the ONE datagram socket of one relay connection, through
// the integrator's WithMediaPacketConn factory when there is one.
//
// The fan-out opens a socket per offered relay, and EVERY one of them must
// come from the factory: a relay socket bound on the host's default interface
// is media leaving by a route the integrator never chose, which is the whole
// reason WithMediaPacketConn exists. So each connection gets its own
// relaySocket wrapping the same factory, rather than the factory being handed
// to the relay package once and trusted to be asked again.
//
// It also owns the socket of an ABANDONED connect. relay.ConnectRelayMedia
// takes no context, so a connect given up on — the call ended mid-handshake,
// or the 12 s timeout fired — kept running with its socket open until pion's
// own handshake timeout, and if it then SUCCEEDED its channel was never
// closed at all. With media starting at the offer, a caller who hangs up
// while we connect is the ordinary case, and a call nobody answered must not
// hold a relay socket. abandon closes the socket now, which fails the
// handshake, and closes the channel if the connect wins the race anyway.
type relaySocket struct {
	open func(*net.UDPAddr) (net.PacketConn, error)

	mu        sync.Mutex
	conn      net.PacketConn
	abandoned bool
}

var errRelayConnectAbandoned = errors.New("meowcaller: relay connect abandoned")

// hostRelaySocket is relay.ConnectRelayMedia's own fallback, spelled here so a
// client with no factory still has its socket tracked.
func hostRelaySocket(*net.UDPAddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
}

func newRelaySocket(open func(*net.UDPAddr) (net.PacketConn, error)) *relaySocket {
	if open == nil {
		open = hostRelaySocket
	}
	return &relaySocket{open: open}
}

// dial is what relay.WithPacketConn calls, once per connection.
func (s *relaySocket) dial(addr *net.UDPAddr) (net.PacketConn, error) {
	conn, err := s.open(addr)
	if err != nil || conn == nil {
		return conn, err
	}
	s.mu.Lock()
	s.conn = conn
	abandoned := s.abandoned
	s.mu.Unlock()
	if abandoned {
		_ = conn.Close()
		return nil, errRelayConnectAbandoned
	}
	return conn, nil
}

type relayConnectResult struct {
	ch  *relay.RelayMediaChannel
	err error
}

// abandon gives up on a connect still in flight: it closes the socket, and
// closes the channel if the connect completes anyway.
func (s *relaySocket) abandon(done <-chan relayConnectResult) {
	s.mu.Lock()
	s.abandoned = true
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	go func() {
		if r := <-done; r.err == nil && r.ch != nil {
			_ = r.ch.Close()
		}
	}()
}
