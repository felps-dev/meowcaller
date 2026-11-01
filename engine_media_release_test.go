package meowcaller

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/sctp"
)

// silentRelay is a loopback stand-in for a WhatsApp relay that completes the
// DTLS and SCTP handshakes, swallows everything sent to it and never sends a
// single datagram back — the shape of a relay once the caller has gone. It is
// the case the in-flight-connect tests cannot reach: the fan-out is UP, and
// only a cancellation can end the media loop's receive.
type silentRelay struct {
	ln       net.Listener
	received atomic.Int64
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    []net.Conn
}

func newSilentRelay(t *testing.T) *silentRelay {
	t.Helper()
	cert, err := selfsign.GenerateSelfSignedWithDNS("relay")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := dtls.Listen("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := &silentRelay{ln: ln}
	r.wg.Add(1)
	go r.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		r.mu.Lock()
		for _, c := range r.conns {
			_ = c.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return r
}

func (r *silentRelay) serve() {
	defer r.wg.Done()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		r.conns = append(r.conns, conn)
		r.mu.Unlock()
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer conn.Close()
			assoc, err := sctp.Server(sctp.Config{NetConn: conn, LoggerFactory: logging.NewDefaultLoggerFactory()})
			if err != nil {
				return
			}
			defer assoc.Close()
			stream, err := assoc.AcceptStream()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			for {
				if _, err := stream.Read(buf); err != nil {
					return
				}
				r.received.Add(1)
			}
		}()
	}
}

func (r *silentRelay) port() uint16 { return uint16(r.ln.Addr().(*net.UDPAddr).Port) }

// trackedSockets is a WithMediaPacketConn factory handing out real loopback
// sockets, recording whether each was closed.
type trackedSockets struct {
	mu    sync.Mutex
	conns []*trackedConn
}

type trackedConn struct {
	net.PacketConn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

func (s *trackedSockets) open(*net.UDPAddr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{PacketConn: conn}
	s.mu.Lock()
	s.conns = append(s.conns, tc)
	s.mu.Unlock()
	return tc, nil
}

func (s *trackedSockets) counts() (opened, closed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		if c.closed.Load() {
			closed++
		}
	}
	return len(s.conns), closed
}

func loopbackOffer(a, b *silentRelay) *relayData {
	rd := twoRelayOffer()
	rd.endpoints[0].addresses = []relayAddress{{ipv4: "127.0.0.1", port: a.port()}}
	rd.endpoints[1].addresses = []relayAddress{{ipv4: "127.0.0.1", port: b.port()}}
	return rd
}

// connectedEarlyMedia rings an inbound call whose two offered relays are live
// loopback relays, and returns once both are connected and have received the
// call's traffic.
func connectedEarlyMedia(t *testing.T) (*engine, *Call, *trackedSockets) {
	t.Helper()
	a, b := newSilentRelay(t), newSilentRelay(t)
	socks := &trackedSockets{}
	eng, call, _ := earlyMediaEngine(socks.open)
	eng.calls["CID"].relay = loopbackOffer(a, b)

	eng.ringInbound("CID", peerJID(), creatorJID(), false, call)
	waitUntil(t, "both relays connected and receiving the call's traffic", func() bool {
		return a.received.Load() > 0 && b.received.Load() > 0
	})
	if opened, closed := socks.counts(); opened != 2 || closed != 0 {
		t.Fatalf("after connect: %d sockets opened, %d closed; want 2 open", opened, closed)
	}
	return eng, call, socks
}

func waitSocketsClosed(t *testing.T, socks *trackedSockets, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if opened, closed := socks.counts(); opened > 0 && closed == opened {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	opened, closed := socks.counts()
	t.Fatalf("%s: %d of %d relay sockets closed 3 s later — a silent relay holds the media loop's receive, and nothing else ends it", what, closed, opened)
}

// TestATerminatedCallReleasesConnectedRelaySockets: once the fan-out is UP,
// ending the call must close every relay socket even if no relay ever sends
// another datagram. The receive loop checks its context only between
// datagrams, so without a cancellation that closes the fan-out it waits on
// silent relays for good — with early media, on every offer nobody answers.
func TestATerminatedCallReleasesConnectedRelaySockets(t *testing.T) {
	eng, _, socks := connectedEarlyMedia(t)
	eng.onTerminate("CID", "timeout")
	waitSocketsClosed(t, socks, "terminate")
}

// TestTheRingLimitReleasesConnectedRelaySockets is the same property when the
// terminate never arrives and the ring limit is what stops the media.
func TestTheRingLimitReleasesConnectedRelaySockets(t *testing.T) {
	old := earlyMediaRingLimit
	earlyMediaRingLimit = 2 * time.Second
	t.Cleanup(func() { earlyMediaRingLimit = old })

	_, _, socks := connectedEarlyMedia(t)
	time.Sleep(earlyMediaRingLimit)
	waitSocketsClosed(t, socks, "ring limit")
}
