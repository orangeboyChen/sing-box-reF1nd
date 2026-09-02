package ninjav2

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	boxTLS "github.com/sagernet/sing-box/common/tls"
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
	outbound.Register[option.NinjaV2OutboundOptions](registry, C.TypeNinjaV2, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger       logger.ContextLogger
	dialer       N.Dialer
	serverAddr   M.Socksaddr
	method       Method
	password     string
	nodePassword string
	passInfo     string
	passVersion  int
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.NinjaV2OutboundOptions) (adapter.Outbound, error) {
	method, err := ParseMethod(options.Method)
	if err != nil {
		return nil, err
	}
	decoded, err := Decode(Encoded{Server: options.Server, Port: int(options.ServerPort), Password: options.Password, NodePassword: options.NodePassword})
	if err != nil {
		return nil, err
	}
	if decoded.Port < 1 || decoded.Port > 65535 {
		return nil, exceptions.New("invalid NinjaV2 decoded port")
	}
	options.Server, options.ServerPort, options.NodePassword = decoded.Server, uint16(decoded.Port), decoded.NodePassword
	if options.Server == "" || options.ServerPort == 0 || options.Password == "" || options.NodePassword == "" {
		return nil, exceptions.New("missing NinjaV2 server or credentials")
	}
	if options.PassInfo == "" {
		return nil, exceptions.New("missing NinjaV2 PASS-INFO")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := boxTLS.NewClient(ctx, logger, options.Server, *options.TLS)
		if err != nil {
			return nil, err
		}
		outboundDialer = boxTLS.NewDialer(outboundDialer, tlsConfig)
	}
	networks := []string{N.NetworkTCP}
	if options.UDP {
		networks = append(networks, N.NetworkUDP)
	}
	return &Outbound{Adapter: outbound.NewAdapterWithDialerOptions(C.TypeNinjaV2, tag, networks, options.DialerOptions), logger: logger, dialer: outboundDialer, serverAddr: options.ServerOptions.Build(), method: method, password: options.Password, nodePassword: options.NodePassword, passInfo: options.PassInfo, passVersion: options.PassVersion}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP && !common.Contains(h.Network(), N.NetworkUDP) {
		return nil, exceptions.New("NinjaV2 UDP is not enabled")
	}
	if N.NetworkName(network) != N.NetworkTCP && N.NetworkName(network) != N.NetworkUDP {
		return nil, exceptions.Extend(N.ErrUnknownNetwork, network)
	}
	if N.NetworkName(network) == N.NetworkTCP {
		ctx, metadata := adapter.ExtendContext(ctx)
		metadata.Outbound, metadata.Destination = h.Tag(), destination
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	}
	return h.dialPass(ctx, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !common.Contains(h.Network(), N.NetworkUDP) {
		return nil, exceptions.New("NinjaV2 UDP is not enabled")
	}
	connection, err := h.dialPass(ctx, destination)
	if err != nil {
		return nil, err
	}
	return &packetConn{Conn: connection, destination: destination}, nil
}

func (h *Outbound) dialPass(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	connection, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	wrapped, err := NewPassConn(connection, h.method, h.password, h.nodePassword, h.passInfo, h.passVersion, toDestination(destination))
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return wrapped, nil
}

type packetConn struct {
	net.Conn
	destination M.Socksaddr
}

func (c *packetConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	count, err := c.Read(buffer)
	return count, c.destination, err
}
func (c *packetConn) WriteTo(buffer []byte, _ net.Addr) (int, error) { return c.Write(buffer) }
func (c *packetConn) SetDeadline(deadline time.Time) error           { return c.Conn.SetDeadline(deadline) }
func toDestination(destination M.Socksaddr) Destination {
	if destination.IsFqdn() {
		return Destination{Host: destination.Fqdn, Port: destination.Port}
	}
	return Destination{Host: destination.Addr.String(), Port: destination.Port}
}
