# Ninja

```json
{
  "type": "ninja",
  "tag": "ninja-out",
  "server": "example.com",
  "server_port": 443,
  "method": "aes-128-gcm",
  "password": "password",
  "node_password": "node-password"
}
```

Ninja uses an encrypted TCP stream. UDP can be carried over that stream with
UDP-over-TCP v2 when `udp` and `udp-over-tcp` are enabled. `method` supports `aes-128-gcm`, `aes-192-gcm`,
`aes-256-gcm`, and `chacha20-ietf-poly1305`.

Ninja subscription node envelopes are decoded when the outbound is created.

## Provider

Providers import `type: ninja` entries from the Ninja subscription YAML
document's `proxies` list. This is a provider-specific extension rather than a
standard Mihomo proxy type. Other subscription fields, including rules, groups,
and DNS settings, are ignored.

```json
{
  "providers": [
    {
      "tag": "ninja",
      "type": "remote",
      "url": "https://example.com/subscription?tag=ninja",
      "path": "./providers/ninja.yaml",
      "user_agent": "clash-ninja/openwrt",
      "update_interval": "12h"
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy",
      "outbounds": ["direct"],
      "providers": ["ninja"]
    },
    { "type": "direct", "tag": "direct" }
  ]
}
```

Provider content is loaded before the outbound graph is created. A failed
remote request falls back to the configured `path` cache when present. Provider
updates take effect when the surrounding configuration is reloaded. The URL
must include `tag=ninja` to request the Ninja subscription format. Such remote
providers use `clash-ninja/openwrt` as their default `User-Agent`; set
`user_agent` to override it.
