package parser

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

func TestOverrideAnyTLSOptions(t *testing.T) {
	testCases := []struct {
		name                   string
		clientMetadata         *string
		disableReuse           bool
		override               *option.OverrideAnyTLSOptions
		expectedClientMetadata *string
		expectedDisableReuse   bool
	}{
		{
			name: "preserve unset",
		},
		{
			name:                   "preserve value",
			clientMetadata:         common.Ptr("original-client/1.0"),
			disableReuse:           true,
			expectedClientMetadata: common.Ptr("original-client/1.0"),
			expectedDisableReuse:   true,
		},
		{
			name:           "clear",
			clientMetadata: common.Ptr("original-client/1.0"),
			disableReuse:   true,
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr(""),
				DisableReuse:   common.Ptr(false),
			},
			expectedClientMetadata: common.Ptr(""),
		},
		{
			name: "replace",
			override: &option.OverrideAnyTLSOptions{
				ClientMetadata: common.Ptr("custom-client/1.0"),
				DisableReuse:   common.Ptr(true),
			},
			expectedClientMetadata: common.Ptr("custom-client/1.0"),
			expectedDisableReuse:   true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbounds := overrideOutbounds([]option.Outbound{{
				Type: C.TypeAnyTLS,
				Options: &option.AnyTLSOutboundOptions{
					ClientMetadata: testCase.clientMetadata,
					DisableReuse:   testCase.disableReuse,
				},
			}}, nil, nil, testCase.override, nil, "")
			options := outbounds[0].Options.(*option.AnyTLSOutboundOptions)
			require.Equal(t, testCase.expectedClientMetadata, options.ClientMetadata)
			require.Equal(t, testCase.expectedDisableReuse, options.DisableReuse)
		})
	}
}

func TestOverrideNinjaTLSOptions(t *testing.T) {
	for _, outbound := range []option.Outbound{
		{
			Type: C.TypeNinja,
			Options: &option.NinjaOutboundOptions{
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "original.example"},
				},
			},
		},
		{
			Type: C.TypeNinjaV2,
			Options: &option.NinjaV2OutboundOptions{
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "original.example"},
				},
			},
		},
	} {
		t.Run(outbound.Type, func(t *testing.T) {
			outbounds := overrideOutbounds(
				[]option.Outbound{outbound},
				nil,
				&option.OverrideTLSOptions{
					ServerName: common.Ptr("override.example"),
					Insecure:   common.Ptr(true),
				},
				nil,
				nil,
				"",
			)
			var tlsOptions *option.OutboundTLSOptions
			switch options := outbounds[0].Options.(type) {
			case *option.NinjaOutboundOptions:
				tlsOptions = options.TLS
			case *option.NinjaV2OutboundOptions:
				tlsOptions = options.TLS
			}
			require.NotNil(t, tlsOptions)
			require.Equal(t, "override.example", tlsOptions.ServerName)
			require.True(t, tlsOptions.Insecure)
		})
	}
}
