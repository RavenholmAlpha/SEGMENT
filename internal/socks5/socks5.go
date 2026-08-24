// Package socks5 implements the RFC 1928 SOCKS5 ingress: TCP CONNECT
// and UDP ASSOCIATE, both backed by tunneled channels.
package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// UDPFlow is one tunneled UDP flow (per destination).
type UDPFlow interface {
	WriteTo(dgram []byte) error
	ReadFrom(buf []byte) (int, error)
	Close() error
}

// Handler connects the SOCKS5 ingress to the tunnel egress.
type Handler struct {
	DialTCP func(addr string, port uint16) (net.Conn, error)
	DialUDP func(addr string, port uint16) (UDPFlow, error)
}

// Serve accepts SOCKS5 connections on l until it closes. A zero-value
// Handler (nil DialTCP/DialUDP) is rejected up front instead of
// panicking on the first CONNECT/UDP datagram.
func (h *Handler) Serve(l net.Listener) error {
	if h.DialTCP == nil || h.DialUDP == nil {
		return errors.New("socks5: Handler requires DialTCP and DialUDP")
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go h.handle(conn)
	}
}

var errNoAcceptableMethods = errors.New("socks5: no acceptable auth methods")

func (h *Handler) handle(conn net.Conn) {
	defer conn.Close()
	if err := handshake(conn); err != nil {
		return
	}
	cmd, atyp, addr, port, err := readRequest(conn)
	if err != nil {
		return
	}
	switch cmd {
	case 1: // CONNECT
		h.handleConnect(conn, addr, port)
	case 3: // UDP ASSOCIATE
		h.handleUDP(conn, atyp, addr, port)
	default:
		_ = writeReply(conn, 0x07) // command not supported
	}
}

// handshake negotiates version 5, no-auth.
func handshake(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return errors.New("socks5: bad version")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == 0 { // NO AUTH
			_, err := conn.Write([]byte{5, 0})
			return err
		}
	}
	_, _ = conn.Write([]byte{5, 0xFF})
	return errNoAcceptableMethods
}

// readRequest parses VER CMD RSV ATYP DST.ADDR DST.PORT.
func readRequest(conn net.Conn) (cmd byte, atyp byte, addr string, port uint16, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, 0, "", 0, err
	}
	if hdr[0] != 5 {
		return 0, 0, "", 0, errors.New("socks5: bad version")
	}
	if hdr[2] != 0 {
		return 0, 0, "", 0, errors.New("socks5: bad rsv")
	}
	cmd, atyp = hdr[1], hdr[3]
	switch atyp {
	case 1: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return 0, 0, "", 0, err
		}
		addr = net.IP(ip[:]).String()
	case 3: // domain
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return 0, 0, "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return 0, 0, "", 0, err
		}
		addr = string(b)
	case 4: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return 0, 0, "", 0, err
		}
		addr = net.IP(ip[:]).String()
	default:
		return 0, 0, "", 0, errors.New("socks5: bad atyp")
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return 0, 0, "", 0, err
	}
	return cmd, atyp, addr, binary.BigEndian.Uint16(p[:]), nil
}

// writeReply sends VER REP RSV ATYP BND.ADDR BND.PORT (0.0.0.0:0).
func writeReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func (h *Handler) handleConnect(conn net.Conn, addr string, port uint16) {
	tc, err := h.DialTCP(addr, port)
	if err != nil {
		_ = writeReply(conn, 0x05) // connection refused
		return
	}
	defer tc.Close()
	if err := writeReply(conn, 0x00); err != nil {
		return
	}
	relay(conn, tc)
}

// relay copies bytes both ways. As soon as either leg finishes (EOF,
// error or a reset), the other leg is closed so its blocked copy
// returns: a half-closed or silently-dropped peer must not pin two
// goroutines and both sockets indefinitely. Closing a leg also ripples
// through the tunnel (FRAME_CLOSE) to the server side.
func relay(a net.Conn, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = b.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = a.Close()
	}()
	wg.Wait()
}

// maxUDPFlows caps the number of concurrent per-destination UDP flows
// per ASSOCIATE session; a stray/malicious client can otherwise grow
// goroutines, tunnel streams and memory without bound.
const maxUDPFlows = 128

// udpIdleTimeout ends an ASSOCIATE session that stopped receiving
// datagrams (a client that vanished without closing its control
// connection must not pin the UDP socket, flows and goroutines).
const udpIdleTimeout = 5 * time.Minute

// handleUDP runs the UDP ASSOCIATE: it binds a local UDP socket,
// replies with its address, and relays datagrams between the client
// and per-destination tunnel flows. Replies are written by each flow's
// own drain goroutine directly to the UDP socket (a sampled, time-ticked
// pump would back-pressure the tunnel flow-control once a flow sustains
// more than a couple of datagrams per tick, killing the whole h2
// connection).
func (h *Handler) handleUDP(conn net.Conn, atyp byte, reqAddr string, reqPort uint16) {
	// Use an explicit IPv4 socket for predictable addresses across
	// platforms (dual-stack sockets report IPv6 wildcard addresses and
	// complicate peer replies).
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return
	}
	defer pc.Close()

	// Reply with a routable address: the server's own local end of the
	// client's TCP control connection (the wildcard 0.0.0.0 is not a
	// valid destination for the client's datagrams).
	var replyIP net.IP
	if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok && ta.IP != nil {
		replyIP = ta.IP.To4()
	}
	if replyIP == nil {
		replyIP = net.IPv4(127, 0, 0, 1)
	}
	replyPort := pc.LocalAddr().(*net.UDPAddr).Port
	if err := writeUDPReply(conn, replyIP, replyPort); err != nil {
		return
	}

	// The client's UDP endpoint: prefer the ASSOCIATE-request address;
	// fall back to learning it from the first datagram.
	var peer *net.UDPAddr
	if reqPort != 0 && reqAddr != "" && reqAddr != "0.0.0.0" && reqAddr != "::" {
		peer = &net.UDPAddr{IP: net.ParseIP(reqAddr), Port: int(reqPort)}
	}

	flows := newFlowMap()
	defer flows.closeAll() // tear down any flows whose drain goroutines exit via session teardown

	// Session teardown: one goroutine watches the control connection
	// for an orderly close (clients close it when done; without this
	// probe a closed control connection would leave the whole
	// ASSOCIATE session — socket, flows, goroutines — resident
	// forever). The UDP socket deadline below enforces a datagram
	// idle timeout as a second, independent exit.
	stopTeardown := make(chan struct{})
	teardownDone := make(chan struct{})
	go func() {
		defer close(teardownDone)
		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(24 * time.Hour))
		for {
			if _, err := conn.Read(buf); err != nil {
				return // EOF (peer closed) or read failure: end session
			}
			// RFC 1928: no further commands on this connection. A
			// well-behaved client never sends bytes here.
		}
	}()
	shutdown := func() { close(stopTeardown); <-teardownDone }
	defer shutdown()

	// Inbound pump: parse client datagrams, route to flows.
	buf := make([]byte, 64<<10)
	pc.SetReadDeadline(time.Now().Add(udpIdleTimeout))
	for {
		select {
		case <-stopTeardown:
			return
		default:
		}
		n, src, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pc.SetReadDeadline(time.Now().Add(udpIdleTimeout)) // datagram resets idle
		if peer == nil {
			peer = src
		}
		if !sameAddr(src, peer) {
			continue // ignore stray datagrams
		}
		dst, port, payload, ok := parseDatagram(buf[:n])
		if !ok {
			continue
		}
		flow, newFlow, err := flows.getOrCreate(dst, port, h.DialUDP)
		if err != nil {
			continue // flow cap reached or dial failed: drop datagram
		}
		if newFlow {
			// Drain the flow straight back to the client socket. No
			// intermediate sampled pump: every reply is written as soon
			// as it arrives, so steady high-rate UDP egress can never
			// back up the tunnel flow control.
			go func(f UDPFlow) {
				inner := make([]byte, 64<<10)
				for {
					n, err := f.ReadFrom(inner)
					if err != nil {
						flows.remove(dst, port)
						return
					}
					if n <= 0 {
						continue
					}
					ob := make([]byte, 0, n+64)
					ob = append(ob, 0, 0, 0)
					ob = appendAddr(ob, dst, port)
					ob = append(ob, inner[:n]...)
					if peer != nil {
						_, _ = pc.WriteToUDP(ob, peer)
					}
				}
			}(flow)
		}
		if err := flow.WriteTo(payload); err != nil {
			flows.remove(dst, port)
		}
	}
}

// flowMap tracks per-destination UDP flows.
type flowMap struct {
	mu    sync.Mutex
	flows map[string]*flowEntry
}

type flowEntry struct {
	addr string
	port uint16
	flow UDPFlow
}

func newFlowMap() *flowMap {
	return &flowMap{flows: make(map[string]*flowEntry)}
}

func (m *flowMap) key(addr string, port uint16) string {
	return net.JoinHostPort(addr, strconv.Itoa(int(port)))
}

// getOrCreate returns the flow for (addr, port), dialing one on first
// use. The dial runs outside the lock: a blocked tunnel dial must not
// freeze the whole flow map. Concurrent dials for the same destination
// are reconciled by the second lookup.
func (m *flowMap) getOrCreate(addr string, port uint16, dial func(string, uint16) (UDPFlow, error)) (UDPFlow, bool, error) {
	k := m.key(addr, port)
	m.mu.Lock()
	if e, ok := m.flows[k]; ok {
		m.mu.Unlock()
		return e.flow, false, nil
	}
	if len(m.flows) >= maxUDPFlows {
		m.mu.Unlock()
		return nil, false, errors.New("socks5: too many UDP flows")
	}
	m.mu.Unlock()

	f, err := dial(addr, port)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	if e, ok := m.flows[k]; ok {
		m.mu.Unlock()
		_ = f.Close() // another dial won the race
		return e.flow, false, nil
	}
	m.flows[k] = &flowEntry{addr: addr, port: port, flow: f}
	m.mu.Unlock()
	return f, true, nil
}

// remove deletes and closes a flow. The Close happens outside the lock
// (it writes FRAME_CLOSE over the tunnel); UDPFlow.Close is idempotent,
// so concurrent removals are safe.
func (m *flowMap) remove(addr string, port uint16) {
	k := m.key(addr, port)
	m.mu.Lock()
	e, ok := m.flows[k]
	if ok {
		delete(m.flows, k)
	}
	m.mu.Unlock()
	if ok {
		_ = e.flow.Close()
	}
}

func (m *flowMap) closeAll() {
	m.mu.Lock()
	all := make([]*flowEntry, 0, len(m.flows))
	for _, e := range m.flows {
		all = append(all, e)
	}
	m.flows = make(map[string]*flowEntry)
	m.mu.Unlock()
	for _, e := range all {
		_ = e.flow.Close()
	}
}

// parseDatagram parses a SOCKS5 UDP datagram (RSV FRAG ATYP ADDR PORT DATA).
func parseDatagram(b []byte) (addr string, port uint16, payload []byte, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", 0, nil, false
	}
	atyp := b[3]
	i := 4
	switch atyp {
	case 1:
		if len(b) < i+4 {
			return "", 0, nil, false
		}
		addr = net.IP(b[i : i+4]).String()
		i += 4
	case 3:
		if len(b) < i+1 {
			return "", 0, nil, false
		}
		l := int(b[i])
		i++
		if len(b) < i+l {
			return "", 0, nil, false
		}
		addr = string(b[i : i+l])
		i += l
	case 4:
		if len(b) < i+16 {
			return "", 0, nil, false
		}
		addr = net.IP(b[i : i+16]).String()
		i += 16
	default:
		return "", 0, nil, false
	}
	if len(b) < i+2 {
		return "", 0, nil, false
	}
	port = binary.BigEndian.Uint16(b[i : i+2])
	return addr, port, b[i+2:], true
}

// appendAddr serializes an address into SOCKS5 UDP header form.
func appendAddr(b []byte, addr string, port uint16) []byte {
	if ip := net.ParseIP(addr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 1)
			b = append(b, v4...)
		} else {
			b = append(b, 4)
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, 3, byte(len(addr)))
		b = append(b, addr...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(b, p[:]...)
}

// writeUDPReply writes the SOCKS5 UDP ASSOCIATE reply: a 10-byte IPv4
// bound-address response.
func writeUDPReply(conn net.Conn, ip net.IP, port int) error {
	if ip == nil {
		ip = net.IPv4zero
	}
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IPv4zero.To4()
	}
	b := []byte{5, 0, 0, 1}
	b = append(b, v4...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	b = append(b, p[:]...)
	_, err := conn.Write(b)
	return err
}

func sameAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Port != b.Port {
		return false
	}
	return a.IP.Equal(b.IP)
}
