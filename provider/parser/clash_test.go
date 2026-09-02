package parser

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestParseClashSnellObfsOptions(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: snell-out
    type: snell
    server: 127.0.0.1
    port: 1080
    psk: password
    version: 5
    udp: true
    obfs-opts:
      mode: http
      host: example.com
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	snellOptions, ok := outbounds[0].Options.(*option.SnellOutboundOptions)
	require.True(t, ok)
	require.Equal(t, 5, snellOptions.Version)
	require.Equal(t, option.NetworkList("tcp\nudp"), snellOptions.Network)
	require.Equal(t, "http", snellOptions.ObfsOptions.ObfsMode)
	require.Equal(t, "example.com", snellOptions.ObfsOptions.ObfsHost)
}

func TestParseClashAnyTLSDisableReuse(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: anytls-out
    type: anytls
    server: 127.0.0.1
    port: 443
    password: password
    disable-reuse: true
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	anyTLSOptions, ok := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
	require.True(t, ok)
	require.True(t, anyTLSOptions.DisableReuse)
}

func TestParseClashNinja(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `
proxies:
  - name: ninja-out
    type: ninja
    server: encoded.example
    port: 12345
    method: aes-128-gcm
    password: password
    node_password: node-password
proxy-groups:
  - name: ignored
    type: select
rules:
  - MATCH,DIRECT
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)

	ninjaOptions, ok := outbounds[0].Options.(*option.NinjaOutboundOptions)
	require.True(t, ok)
	require.Equal(t, "encoded.example", ninjaOptions.Server)
	require.Equal(t, uint16(12345), ninjaOptions.ServerPort)
	require.Equal(t, "aes-128-gcm", ninjaOptions.Method)
	require.Equal(t, "password", ninjaOptions.Password)
	require.Equal(t, "node-password", ninjaOptions.NodePassword)
}

func TestParseClashNinjaV2PassInfo(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.Background(), `#!PASS-INFO encoded-pass
proxies:
  - name: ninja-v2-out
    type: ninja
    server: encoded.example
    port: 12345
    method: aes-128-gcm
    password: password
    node_password: node-password
`)
	require.NoError(t, err)
	require.Empty(t, endpoints)
	require.Len(t, outbounds, 1)
	require.Equal(t, "ninjav2", outbounds[0].Type)
	ninjaOptions := outbounds[0].Options.(*option.NinjaV2OutboundOptions)
	require.Equal(t, "encoded-pass", ninjaOptions.PassInfo)
	require.Equal(t, 1, ninjaOptions.PassVersion)
}
