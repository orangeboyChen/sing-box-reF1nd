package option

type NinjaOutboundOptions struct {
	DialerOptions
	ServerOptions
	Method       string             `json:"method" enum:"aes-128-gcm,aes-192-gcm,aes-256-gcm,chacha20-ietf-poly1305"`
	Password     string             `json:"password"`
	NodePassword string             `json:"node_password"`
	UDP          bool               `json:"udp,omitempty"`
	UDPOverTCP   *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
}

type NinjaV2OutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Method       string             `json:"method" enum:"aes-128-gcm,aes-192-gcm,aes-256-gcm"`
	Password     string             `json:"password"`
	NodePassword string             `json:"node_password"`
	UDP          bool               `json:"udp,omitempty"`
	UDPOverTCP   *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	PassInfo     string             `json:"pass_info,omitempty"`
	PassVersion  int                `json:"pass_version,omitempty"`
}
