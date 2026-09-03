package ninjav2

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/ninja"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NinjaV2OutboundOptions](registry, C.TypeNinjaV2, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger       logger.ContextLogger
	transport    adapter.V2RayClientTransport
	passMethod   Method
	passPassword string
	coreMethod   ninja.Method
	corePassword string
	paddingMode  string
	paddingMin   int
	paddingMax   int
	nodePassword string
	uotClient    *uot.Client
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.NinjaV2OutboundOptions) (adapter.Outbound, error) {
	if options.PassInfo == "" {
		return nil, E.New("missing NinjaV2 PASS-INFO")
	}
	info, err := decodePassInfo(options.PassInfo, options.PassVersion)
	if err != nil {
		return nil, E.Cause(err, "decode NinjaV2 PASS-INFO")
	}
	if !info.Set.Pass {
		return nil, E.New("NinjaV2 PASS transport is disabled")
	}
	if info.Set.Network != C.V2RayTransportTypeWebsocket {
		return nil, E.New("unsupported NinjaV2 transport: ", info.Set.Network)
	}
	passMethod, err := ParseMethod(info.Set.PassOptions.Method)
	if err != nil {
		return nil, err
	}
	if info.Set.PassOptions.Password == "" {
		return nil, E.New("missing NinjaV2 PASS password")
	}
	coreMethod, err := ninja.ParseMethod(options.Method)
	if err != nil {
		return nil, err
	}
	decoded, err := Decode(Encoded{Server: options.Server, Port: int(options.ServerPort), Password: options.Password, NodePassword: options.NodePassword})
	if err != nil {
		return nil, err
	}
	if decoded.Port < 1 || decoded.Port > 65535 {
		return nil, E.New("invalid NinjaV2 decoded port")
	}
	options.Server = info.replaceServer(decoded.Server)
	options.ServerPort = uint16(decoded.Port)
	if options.Server == "" {
		return nil, E.New("missing NinjaV2 decoded server")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	tlsOptions := option.OutboundTLSOptions{Enabled: info.Set.TLS, ServerName: info.Set.ServerName, Insecure: info.Set.SkipCertVerify}
	var tlsConfig boxTLS.Config
	if tlsOptions.Enabled {
		tlsConfig, err = boxTLS.NewClient(ctx, logger, options.Server, tlsOptions)
		if err != nil {
			return nil, err
		}
	}
	headers := make(badoption.HTTPHeader, len(info.Set.WebsocketOptions.Headers))
	for name, value := range info.Set.WebsocketOptions.Headers {
		headers[name] = badoption.Listable[string]{value}
	}
	serverAddr := options.ServerOptions.Build()
	transport, err := v2ray.NewClientTransport(ctx, outboundDialer, serverAddr, option.V2RayTransportOptions{
		Type: C.V2RayTransportTypeWebsocket,
		WebsocketOptions: option.V2RayWebsocketOptions{
			Path: info.Set.WebsocketOptions.Path, Headers: headers,
		},
	}, tlsConfig)
	if err != nil {
		return nil, E.Cause(err, "create NinjaV2 WebSocket transport")
	}
	networks := []string{N.NetworkTCP}
	if options.UDP {
		networks = append(networks, N.NetworkUDP)
	}
	result := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeNinjaV2, tag, networks, options.DialerOptions),
		logger:  logger, transport: transport, passMethod: passMethod, passPassword: info.Set.PassOptions.Password,
		coreMethod: coreMethod, corePassword: options.Password,
		paddingMode: info.Set.PassOptions.PaddingMode, paddingMin: info.Set.PassOptions.PaddingMin,
		paddingMax:   info.Set.PassOptions.PaddingRandomMax,
		nodePassword: decoded.NodePassword,
	}
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		result.uotClient = &uot.Client{Dialer: (*ninjaV2Dialer)(result), Version: uotOptions.Version}
	}
	return result, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return (*ninjaV2Dialer)(h).DialContext(ctx, network, destination)
	case N.NetworkUDP:
		if !common.Contains(h.Network(), N.NetworkUDP) {
			return nil, E.New("NinjaV2 UDP is not enabled")
		}
		if h.uotClient == nil {
			return nil, E.New("NinjaV2 UDP requires UDP over TCP")
		}
		h.logger.InfoContext(ctx, "outbound UoT connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !common.Contains(h.Network(), N.NetworkUDP) {
		return nil, E.New("NinjaV2 UDP is not enabled")
	}
	if h.uotClient == nil {
		return nil, E.New("NinjaV2 UDP requires UDP over TCP")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) Close() error {
	return common.Close(h.transport)
}

type ninjaV2Dialer Outbound

func (h *ninjaV2Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	connection, err := h.transport.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	wrapper, err := NewPassConn(connection, h.passMethod, h.passPassword, h.paddingMode, h.paddingMin, h.paddingMax)
	if err != nil {
		connection.Close()
		return nil, err
	}
	return ninja.NewClientConn(wrapper, ninja.Credentials{
		Method: h.coreMethod, Password: h.corePassword, NodePassword: h.nodePassword,
	}, toNinjaDestination(destination)), nil
}

func (h *ninjaV2Dialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("NinjaV2 packet transport requires UDP over TCP")
}

func toNinjaDestination(destination M.Socksaddr) ninja.Destination {
	if destination.IsFqdn() {
		return ninja.Destination{Host: destination.Fqdn, Port: destination.Port}
	}
	return ninja.Destination{Host: destination.Addr.String(), Port: destination.Port}
}
