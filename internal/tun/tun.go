// Package tun reserves the TUN device ingress for the Segment client.
//
// The clients ships with the SOCKS5 ingress (TCP CONNECT + UDP
// ASSOCIATE) fully implemented; a transparent TUN mode is the planned
// alternative ingress (see docs/design.md §9). This package defines the
// device abstraction and an explicit, honest NOT-IMPLEMENTED barrier so
// the surface is stable and the missing piece is unambiguous.
//
// Why not implemented yet: on Windows a TUN driver (e.g. wintun) is
// required for a userspace NIC; on Linux /dev/net/tun with an
// administrator-created interface. Both need per-OS build tags and a
// local privilege story that the pure-Go core deliberately avoids
// today. The wire protocol already carries everything a TUN needs
// (frame-granular Segment frames, UDP flag, FIN/RST semantics).
package tun

import (
	"errors"
	"io"
)

// ErrNotImplemented is returned by Open on platforms without a TUN
// backend compiled in.
var ErrNotImplemented = errors.New("tun: no TUN backend compiled in (SOCKS5 ingress is the supported mode)")

// Device is a Layer-3 packet device: packets written to it leave the
// host on the tunnel; packets from the tunnel appear as reads.
type Device interface {
	io.ReadWriteCloser
	Name() string
}

// Config describes the local TUN interface.
type Config struct {
	Name      string // interface name (OS-defined when empty)
	MTU       int    // default 1200
	Address   string // CIDR for the interface, e.g. 10.7.0.2/24 (platform support varies)
	Routes    []string
	NoGateway bool
}

// Open platforms a TUN device per cfg. Backends: TODO(linux: /dev/net/tun,
// windows: wintun, darwin: utun). Until one is compiled in, every call
// returns ErrNotImplemented so callers degrade gracefully to SOCKS5.
func Open(cfg Config) (Device, error) {
	return nil, ErrNotImplemented
}
