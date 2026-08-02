package ninja

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
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
	return &Outbound{
		Adapter:     outbound.NewAdapterWithDialerOptions(C.TypeNinja, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:      logger,
		dialer:      outboundDialer,
		serverAddr:  options.ServerOptions.Build(),
		credentials: Credentials{Method: method, Password: options.Password, NodePassword: options.NodePassword},
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
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
	return &conn{Conn: connection, credentials: h.credentials, destination: toDestination(destination), handshakeDone: make(chan struct{})}, nil
}

func (h *Outbound) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, exceptions.New("Ninja does not support UDP")
}

type conn struct {
	net.Conn
	credentials   Credentials
	destination   Destination
	clientSalt    []byte
	readSession   *Session
	writeSession  *Session
	buffer        []byte
	writeAccess   sync.Mutex
	handshakeDone chan struct{}
	handshakeOnce sync.Once
	handshakeErr  error
}

func (c *conn) startLocked(payload []byte) error {
	if c.writeSession != nil {
		return nil
	}
	capture := &saltCaptureWriter{Writer: c.Conn}
	writeSession, err := c.credentials.WriteClientHandshake(capture, c.destination, payload, 0)
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

func (c *conn) Write(payload []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.writeSession == nil {
		if err := c.startLocked(payload); err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	if err := c.writeSession.WriteFrame(c.Conn, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
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
