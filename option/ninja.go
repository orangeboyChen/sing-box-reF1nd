package option

type NinjaOutboundOptions struct {
	DialerOptions
	ServerOptions
	Method       string `json:"method" enum:"aes-128-gcm,aes-192-gcm,aes-256-gcm,chacha20-ietf-poly1305"`
	Password     string `json:"password"`
	NodePassword string `json:"node_password"`
}
