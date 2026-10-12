package ninja

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

const websocketALPN = "cs-gw1"

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NinjaOutboundOptions](registry, C.TypeNinja, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger      logger.ContextLogger
	dialer      N.Dialer
	serverAddr  M.Socksaddr
	credentials Credentials
	tlsDialer   boxTLS.Dialer
	transport   adapter.V2RayClientTransport
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
	var tlsConfig boxTLS.Config
	if options.TLS != nil {
		tlsConfig, err = boxTLS.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil {
			h.tlsDialer = boxTLS.NewDialer(outboundDialer, tlsConfig)
		}
	}
	if options.Transport != nil {
		if options.Transport.Type != C.V2RayTransportTypeWebsocket {
			return nil, exceptions.New("unsupported Ninja transport: ", options.Transport.Type)
		}
		if tlsConfig != nil {
			tlsConfig.SetNextProtos([]string{websocketALPN})
		}
		h.transport, err = v2ray.NewClientTransport(ctx, outboundDialer, h.serverAddr, common.PtrValueOrDefault(options.Transport), tlsConfig)
		if err != nil {
			return nil, exceptions.Cause(err, "create Ninja client transport")
		}
	}
	return h, nil
}

func (h *Outbound) dialServer(ctx context.Context) (net.Conn, error) {
	if h.transport != nil {
		return h.transport.DialContext(ctx)
	}
	if h.tlsDialer != nil {
		return h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	}
	return h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		if !common.Contains(h.Network(), N.NetworkUDP) {
			return nil, exceptions.New("Ninja UDP is not enabled")
		}
		connection, err := h.dialServer(ctx)
		if err != nil {
			return nil, err
		}
		return newConn(connection, h.credentials, toDestination(destination), udpNetwork), nil
	}
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, exceptions.Extend(N.ErrUnknownNetwork, network)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound, metadata.Destination = h.Tag(), destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	connection, err := h.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	return newConn(connection, h.credentials, toDestination(destination), tcpNetwork), nil
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !common.Contains(h.Network(), N.NetworkUDP) {
		return nil, exceptions.New("Ninja UDP is not enabled")
	}
	return NewClientPacketConnWithDialer(ctx, h.dialServer, h.credentials, destination)
}

func (h *Outbound) Close() error {
	return common.Close(h.transport)
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
	readDeadline  pipe.Deadline
}

func newConn(connection net.Conn, credentials Credentials, destination Destination, network byte) *conn {
	return &conn{
		Conn:          connection,
		credentials:   credentials,
		destination:   destination,
		network:       network,
		handshakeDone: make(chan struct{}),
		readDeadline:  pipe.MakeDeadline(),
	}
}

// NewClientConn wraps an established transport with the Ninja core protocol.
func NewClientConn(connection net.Conn, credentials Credentials, destination Destination) net.Conn {
	return NewClientConnNetwork(connection, credentials, destination, tcpNetwork)
}

func NewClientConnNetwork(connection net.Conn, credentials Credentials, destination Destination, network byte) net.Conn {
	return newConn(connection, credentials, destination, network)
}

func NewClientPacketConn(connection net.Conn, credentials Credentials, destination M.Socksaddr) net.PacketConn {
	return &packetConn{
		conn:        newConn(connection, credentials, toDestination(destination), udpNetwork),
		destination: destination,
	}
}

type packetDialer func(ctx context.Context) (net.Conn, error)

type packetResult struct {
	payload     []byte
	destination M.Socksaddr
	err         error
}

type oneShotPacketConn struct {
	ctx            context.Context
	cancel         context.CancelFunc
	dialer         packetDialer
	credentials    Credentials
	destination    M.Socksaddr
	results        chan packetResult
	readDeadline   pipe.Deadline
	access         sync.Mutex
	connections    map[net.Conn]struct{}
	localAddr      net.Addr
	readDeadlineAt time.Time
	writeDeadline  time.Time
	closed         bool
}

// NewClientPacketConnWithDialer creates a compatible Ninja UDP packet connection.
// Some Ninja servers stop forwarding DNS after the first response on a
// persistent stream, so port 53 uses one Ninja stream per query.
func NewClientPacketConnWithDialer(ctx context.Context, dialer func(context.Context) (net.Conn, error), credentials Credentials, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.Port != 53 {
		connection, err := dialer(ctx)
		if err != nil {
			return nil, err
		}
		return NewClientPacketConn(connection, credentials, destination), nil
	}
	return newClientOneShotPacketConn(ctx, dialer, credentials, destination), nil
}

func newClientOneShotPacketConn(ctx context.Context, dialer func(context.Context) (net.Conn, error), credentials Credentials, destination M.Socksaddr) net.PacketConn {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &oneShotPacketConn{
		ctx:          ctx,
		cancel:       cancel,
		dialer:       dialer,
		credentials:  credentials,
		destination:  destination,
		results:      make(chan packetResult, 64),
		readDeadline: pipe.MakeDeadline(),
		connections:  make(map[net.Conn]struct{}),
	}
}

func (c *oneShotPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case result := <-c.results:
		if result.err != nil {
			return 0, result.destination, result.err
		}
		count := copy(buffer, result.payload)
		return count, result.destination, nil
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *oneShotPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	destination := c.destination
	if address != nil {
		socksaddr := M.SocksaddrFromNet(address)
		if socksaddr.IsFqdn() || socksaddr.Port != 0 {
			destination = socksaddr
		}
	}
	if destination != c.destination {
		return 0, fmt.Errorf("Ninja UDP destination changed after connection setup")
	}

	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return 0, net.ErrClosed
	}
	writeDeadline := c.writeDeadline
	c.access.Unlock()

	operationCtx, operationCancel := context.WithCancel(c.ctx)
	dialCtx := operationCtx
	dialCancel := func() {}
	if !writeDeadline.IsZero() {
		dialCtx, dialCancel = context.WithDeadline(operationCtx, writeDeadline)
	}
	connection, err := c.dialer(dialCtx)
	dialCancel()
	if err != nil {
		operationCancel()
		return 0, err
	}
	if !writeDeadline.IsZero() {
		if err = connection.SetWriteDeadline(writeDeadline); err != nil {
			operationCancel()
			connection.Close()
			return 0, err
		}
	}

	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		operationCancel()
		connection.Close()
		return 0, net.ErrClosed
	}
	if !c.readDeadlineAt.IsZero() {
		if err = connection.SetReadDeadline(c.readDeadlineAt); err != nil {
			c.access.Unlock()
			operationCancel()
			connection.Close()
			return 0, err
		}
	}
	c.connections[connection] = struct{}{}
	if c.localAddr == nil {
		c.localAddr = connection.LocalAddr()
	}
	c.access.Unlock()

	ninjaConn := newConn(connection, c.credentials, toDestination(destination), udpNetwork)
	count, err := ninjaConn.WriteTo(buffer, toDestination(destination))
	if err != nil {
		c.removeConnection(connection)
		operationCancel()
		connection.Close()
		return count, err
	}
	go c.readOnePacket(operationCtx, operationCancel, connection, ninjaConn)
	return count, nil
}

func (c *oneShotPacketConn) readOnePacket(operationCtx context.Context, operationCancel context.CancelFunc, connection net.Conn, ninjaConn *conn) {
	defer operationCancel()
	defer connection.Close()
	defer c.removeConnection(connection)
	payload, err := ninjaConn.readPacket()
	result := packetResult{destination: c.destination, err: err}
	if err == nil {
		var responseDestination Destination
		responseDestination, result.payload, result.err = decodeUDPResponse(payload)
		if result.err == nil {
			result.destination = M.ParseSocksaddrHostPort(responseDestination.Host, responseDestination.Port)
		}
	}
	select {
	case c.results <- result:
	case <-operationCtx.Done():
	case <-c.ctx.Done():
	}
}

func (c *oneShotPacketConn) removeConnection(connection net.Conn) {
	c.access.Lock()
	delete(c.connections, connection)
	c.access.Unlock()
}

func (c *oneShotPacketConn) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	connections := make([]net.Conn, 0, len(c.connections))
	for connection := range c.connections {
		connections = append(connections, connection)
	}
	c.access.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
	return nil
}

func (c *oneShotPacketConn) LocalAddr() net.Addr {
	c.access.Lock()
	defer c.access.Unlock()
	if c.localAddr != nil {
		return c.localAddr
	}
	return M.Socksaddr{}
}

func (c *oneShotPacketConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

func (c *oneShotPacketConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline.Set(deadline)
	c.access.Lock()
	c.readDeadlineAt = deadline
	var deadlineErr error
	for connection := range c.connections {
		if err := connection.SetReadDeadline(deadline); err != nil && deadlineErr == nil {
			deadlineErr = err
		}
	}
	c.access.Unlock()
	return deadlineErr
}

func (c *oneShotPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.access.Lock()
	c.writeDeadline = deadline
	c.access.Unlock()
	return nil
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

func (c *conn) SetDeadline(deadline time.Time) error {
	if err := c.Conn.SetDeadline(deadline); err != nil {
		return err
	}
	c.readDeadline.Set(deadline)
	return nil
}

func (c *conn) SetReadDeadline(deadline time.Time) error {
	if err := c.Conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	c.readDeadline.Set(deadline)
	return nil
}

func (c *conn) startLocked(payload []byte, paddingLength int) error {
	if c.writeSession != nil {
		return nil
	}
	capture := &saltCaptureWriter{Writer: c.Conn}
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

func (c *conn) startTCPWriteLocked(payload []byte) error {
	paddingLength, initialLength, err := c.planFirstBlock()
	if err != nil {
		return err
	}
	if initialLength > len(payload) {
		initialLength = len(payload)
	}
	var wire bytes.Buffer
	capture := &saltCaptureWriter{Writer: &wire}
	writeSession, err := c.credentials.WriteClientHandshakeNetwork(capture, c.network, c.destination, payload[:initialLength], paddingLength)
	remaining := payload[initialLength:]
	for err == nil && len(remaining) > 0 {
		chunkLength := len(remaining)
		if chunkLength > maxCorePayload {
			chunkLength = maxCorePayload
		}
		var frame bytes.Buffer
		err = writeSession.WriteFrame(&frame, remaining[:chunkLength])
		if err == nil && wire.Len()+frame.Len() > tcpWriteBufferSize {
			err = writeAll(c.Conn, wire.Bytes())
			wire.Reset()
		}
		if err == nil {
			_, err = wire.Write(frame.Bytes())
		}
		remaining = remaining[chunkLength:]
	}
	if err == nil {
		err = writeAll(c.Conn, wire.Bytes())
	}
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
		if c.network == udpNetwork {
			c.writeAccess.Unlock()
			select {
			case <-c.handshakeDone:
			case <-c.readDeadline.Wait():
				return os.ErrDeadlineExceeded
			}
			if c.handshakeErr != nil {
				return c.handshakeErr
			}
			return c.initializeReadSession()
		}
		if err := c.startTCPWriteLocked(nil); err != nil {
			c.writeAccess.Unlock()
			return err
		}
	}
	c.writeAccess.Unlock()
	<-c.handshakeDone
	if c.handshakeErr != nil {
		return c.handshakeErr
	}
	return c.initializeReadSession()
}

func (c *conn) initializeReadSession() error {
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
			if err := c.startLocked(payload, 1); err != nil {
				return 0, err
			}
			return len(payload), nil
		}
		if err := c.startTCPWriteLocked(payload); err != nil {
			return 0, err
		}
		return originalLength, nil
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

func (c *conn) planFirstBlock() (paddingLength int, payloadLength int, err error) {
	destination, err := encodeTransportDestination(c.destination)
	if err != nil {
		return 0, 0, err
	}
	return planFirstBlock(len(destination))
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
