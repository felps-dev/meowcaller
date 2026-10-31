package meowcaller

import (
	"net"

	"github.com/purpshell/meowcaller/diag"
	"github.com/rs/zerolog"
)

// Option configures optional, non-behavioral aspects of the call/media types —
// currently the diagnostic logger. The zero configuration logs nothing.
type Option func(*config)

type config struct {
	log  zerolog.Logger
	diag *diag.Recorder

	mediaPacketConn func(relayAddr *net.UDPAddr) (net.PacketConn, error)

	// relayEndpointObserver is the temporary issue-#40 diagnostic hook. See
	// WithRelayEndpointObserver and engine_relay_diagnostics.go.
	relayEndpointObserver func(RelayEndpointSelection)
}

func resolveConfig(opts []Option) config {
	c := config{log: zerolog.Nop()}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithLogger sets the zerolog logger for debug/trace diagnostics. The library never
// configures logging itself; without this option the types are silent at zero cost.
// Pass the logger from a context, e.g. WithLogger(*zerolog.Ctx(ctx)).
func WithLogger(l zerolog.Logger) Option {
	return func(c *config) { c.log = l }
}

// WithDiagnostics attaches a developer-only *diag.Recorder that dumps exact,
// per-category call diagnostics (including raw secrets and media) to JSONL files.
// This is an opt-in maintainer carve-out from the library's sanitized logging and
// must never be enabled in production. Without it the recorder is nil and every
// diag emit is a no-op at zero cost.
func WithDiagnostics(rec *diag.Recorder) Option {
	return func(c *config) { c.diag = rec }
}

// WithRelayEndpointObserver installs a once-per-call diagnostic callback that
// reports the offer's parsed relay endpoint list and which entry this call's
// media was allocated on.
//
// TEMPORARY: it exists to observe upstream issue purpshell/meowcaller#40 ("no
// inbound audio when the offer carries no is_fna endpoint") from an integrator
// that cannot see the unexported selection, and goes away with the issue. The
// report carries addresses, ports, token IDs and the is_fna flag only — no key
// material, no call key, no media — because it is meant to be readable in
// production logs.
//
// fn runs on the media goroutine, before the relay transport is dialled. It
// must not block.
func WithRelayEndpointObserver(fn func(RelayEndpointSelection)) Option {
	return func(c *config) { c.relayEndpointObserver = fn }
}

// WithMediaPacketConn makes every relay media connection run over the datagram
// socket fn returns instead of a plain host UDP socket, so media can leave through
// the same exit as signalling (a SOCKS5 UDP association).
func WithMediaPacketConn(fn func(relayAddr *net.UDPAddr) (net.PacketConn, error)) Option {
	return func(c *config) { c.mediaPacketConn = fn }
}
