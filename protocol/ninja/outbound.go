package ninja

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NinjaOutboundOptions](registry, C.TypeNinja, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger      logger.ContextLogger
	dialer      N.Dialer
	serverAddr  M.Socksaddr
	credentials Credentials
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.NinjaOutboundOptions) (adapter.Outbound, error) {
	method, err := ParseMethod(options.Method)
	if err != nil {
		return nil, err
	}
	decoded, err := Decode(Encoded{Server: options.Server, Port: int(options.ServerPort), Password: options.Password, NodePassword: options.NodePassword})
	if err != nil {
		return nil, err
	}
	if decoded.Port < 1 || decoded.Port > 65535 {
		return nil, exceptions.New("invalid Ninja decoded port")
	}
	options.Server, options.ServerPort, options.NodePassword = decoded.Server, uint16(decoded.Port), decoded.NodePassword
	if options.Server == "" || options.ServerPort == 0 || options.Password == "" || options.NodePassword == "" {
		return nil, exceptions.New("missing Ninja server or credentials")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	networks := []string{N.NetworkTCP}
	if options.UDP {
		networks = append(networks, N.NetworkUDP)
	}
	h := &Outbound{
		Adapter:     outbound.NewAdapterWithDialerOptions(C.TypeNinja, tag, networks, options.DialerOptions),
		logger:      logger,
		dialer:      outboundDialer,
		serverAddr:  options.ServerOptions.Build(),
		credentials: Credentials{Method: method, Password: options.Password, NodePassword: options.NodePassword},
	}
	return h, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		if !common.Contains(h.Network(), N.NetworkUDP) {
			return nil, exceptions.New("Ninja UDP is not enabled")
		}
		connection, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		return &conn{Conn: connection, credentials: h.credentials, destination: toDestination(destination), network: udpNetwork, handshakeDone: make(chan struct{})}, nil
	}
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, exceptions.Extend(N.ErrUnknownNetwork, network)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound, metadata.Destination = h.Tag(), destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	connection, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	return &conn{Conn: connection, credentials: h.credentials, destination: toDestination(destination), network: tcpNetwork, handshakeDone: make(chan struct{})}, nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !common.Contains(h.Network(), N.NetworkUDP) {
		return nil, exceptions.New("Ninja UDP is not enabled")
	}
	connection, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	return &packetConn{conn: &conn{Conn: connection, credentials: h.credentials, destination: toDestination(destination), network: udpNetwork, handshakeDone: make(chan struct{})}, destination: destination}, nil
}

type conn struct {
	net.Conn
	credentials   Credentials
	destination   Destination
	network       byte
	clientSalt    []byte
	readSession   *Session
	writeSession  *Session
	buffer        []byte
	writeAccess   sync.Mutex
	handshakeDone chan struct{}
	handshakeOnce sync.Once
	handshakeErr  error
}

// NewClientConn wraps an established transport with the Ninja core protocol.
func NewClientConn(connection net.Conn, credentials Credentials, destination Destination) net.Conn {
	return NewClientConnNetwork(connection, credentials, destination, tcpNetwork)
}

func NewClientConnNetwork(connection net.Conn, credentials Credentials, destination Destination, network byte) net.Conn {
	return &conn{Conn: connection, credentials: credentials, destination: destination, network: network, handshakeDone: make(chan struct{})}
}

func NewClientPacketConn(connection net.Conn, credentials Credentials, destination M.Socksaddr) net.PacketConn {
	return &packetConn{
		conn:        &conn{Conn: connection, credentials: credentials, destination: toDestination(destination), network: udpNetwork, handshakeDone: make(chan struct{})},
		destination: destination,
	}
}

type packetConn struct {
	conn        *conn
	destination M.Socksaddr
}

func (c *packetConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	payload, err := c.conn.readPacket()
	if err != nil {
		return 0, c.destination, err
	}
	destination, payload, err := decodeUDPResponse(payload)
	if err != nil {
		return 0, c.destination, fmt.Errorf("decode Ninja UDP response address: %w", err)
	}
	count := copy(buffer, payload)
	return count, M.ParseSocksaddrHostPort(destination.Host, destination.Port), nil
}

func (c *packetConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	destination := c.conn.destination
	if address != nil {
		socksaddr := M.SocksaddrFromNet(address)
		if socksaddr.IsFqdn() || socksaddr.Port != 0 {
			destination = toDestination(socksaddr)
		}
	}
	return c.conn.WriteTo(buffer, destination)
}

func (c *packetConn) Close() error { return c.conn.Close() }

func (c *packetConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *packetConn) SetDeadline(deadline time.Time) error { return c.conn.SetDeadline(deadline) }

func (c *packetConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *packetConn) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}

func (c *conn) startLocked(payload []byte) error {
	if c.writeSession != nil {
		return nil
	}
	capture := &saltCaptureWriter{Writer: c.Conn}
	paddingLength := 0
	if c.network == udpNetwork {
		paddingLength = 1
	}
	writeSession, err := c.credentials.WriteClientHandshakeNetwork(capture, c.network, c.destination, payload, paddingLength)
	c.handshakeOnce.Do(func() {
		c.handshakeErr = err
		if err == nil {
			c.writeSession, c.clientSalt = writeSession, capture.salt
		}
		close(c.handshakeDone)
	})
	return c.handshakeErr
}

func (c *conn) ensureReadSession() error {
	c.writeAccess.Lock()
	if c.writeSession == nil {
		if err := c.startLocked(nil); err != nil {
			c.writeAccess.Unlock()
			return err
		}
	}
	c.writeAccess.Unlock()
	<-c.handshakeDone
	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	if c.readSession != nil {
		return nil
	}
	readSession, initialPayload, err := c.credentials.ReadServerResponse(c.Conn, c.clientSalt)
	if err != nil {
		return err
	}
	c.readSession, c.buffer = readSession, initialPayload
	return nil
}

func (c *conn) Close() error {
	c.handshakeOnce.Do(func() { c.handshakeErr = net.ErrClosed; close(c.handshakeDone) })
	return c.Conn.Close()
}

func (c *conn) Read(buffer []byte) (int, error) {
	if err := c.ensureReadSession(); err != nil {
		return 0, err
	}
	if len(c.buffer) == 0 {
		payload, err := c.readSession.ReadFrame(c.Conn)
		if err != nil {
			return 0, err
		}
		c.buffer = payload
	}
	size := copy(buffer, c.buffer)
	c.buffer = c.buffer[size:]
	return size, nil
}

func (c *conn) readPacket() ([]byte, error) {
	if err := c.ensureReadSession(); err != nil {
		return nil, err
	}
	if len(c.buffer) != 0 {
		payload := c.buffer
		c.buffer = nil
		return payload, nil
	}
	return c.readSession.ReadFrame(c.Conn)
}

func decodeUDPResponse(payload []byte) (Destination, []byte, error) {
	destination, consumed, err := decodeTransportDestination(payload)
	if err != nil {
		return Destination{}, nil, err
	}
	if len(payload) == consumed {
		return Destination{}, nil, io.ErrUnexpectedEOF
	}
	return destination, payload[consumed:], nil
}

func (c *conn) Write(payload []byte) (int, error) {
	return c.WriteTo(payload, c.destination)
}

func (c *conn) WriteTo(payload []byte, destination Destination) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	originalLength := len(payload)
	if c.writeSession == nil {
		if c.network == udpNetwork {
			c.destination = destination
			if err := c.startLocked(payload); err != nil {
				return 0, err
			}
			return len(payload), nil
		}
		initialLimit, err := c.initialPayloadLimit()
		if err != nil {
			return 0, err
		}
		if len(payload) <= initialLimit {
			if err := c.startLocked(payload); err != nil {
				return 0, err
			}
			return len(payload), nil
		}
		if err := c.startLocked(nil); err != nil {
			return 0, err
		}
	}
	if c.network == udpNetwork {
		if len(payload) > maxCorePayload {
			return 0, fmt.Errorf("Ninja UDP datagram is too large: %d", len(payload))
		}
		if destination != c.destination {
			return 0, fmt.Errorf("Ninja UDP destination changed after connection setup")
		}
		if err := c.writeSession.WriteFrame(c.Conn, payload); err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	for len(payload) > 0 {
		chunkLength := len(payload)
		if chunkLength > maxCorePayload {
			chunkLength = maxCorePayload
		}
		if err := c.writeSession.WriteFrame(c.Conn, payload[:chunkLength]); err != nil {
			return 0, err
		}
		payload = payload[chunkLength:]
	}
	return originalLength, nil
}

func (c *conn) initialPayloadLimit() (int, error) {
	destination, err := encodeTransportDestination(c.destination)
	if err != nil {
		return 0, err
	}
	paddingLength := 0
	if c.network == udpNetwork {
		paddingLength = 1
	}
	limit := maxCorePayload
	if handshakeLimit := 0xffff - len(destination) - 2 - paddingLength; handshakeLimit < limit {
		limit = handshakeLimit
	}
	return limit, nil
}

type saltCaptureWriter struct {
	io.Writer
	salt []byte
}

func (w *saltCaptureWriter) Write(payload []byte) (int, error) {
	if w.salt == nil {
		w.salt = append([]byte(nil), payload...)
	}
	return w.Writer.Write(payload)
}

func toDestination(destination M.Socksaddr) Destination {
	if destination.IsFqdn() {
		return Destination{Host: destination.Fqdn, Port: destination.Port}
	}
	return Destination{Host: destination.Addr.String(), Port: destination.Port}
}
