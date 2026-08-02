package remote

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestProviderUserAgent(t *testing.T) {
	testCases := []struct {
		name                string
		providerURL         string
		configuredUserAgent string
		expected            string
	}{
		{
			name:        "ninja tag",
			providerURL: "https://example.com/subscription?tag=ninja",
			expected:    "clash-ninja/openwrt",
		},
		{
			name:        "case insensitive ninja tag",
			providerURL: "https://example.com/subscription?tag=NINJA",
			expected:    "clash-ninja/openwrt",
		},
		{
			name:                "ninja tag takes priority over configured user agent",
			providerURL:         "https://example.com/subscription?tag=ninja",
			configuredUserAgent: "custom-agent",
			expected:            "clash-ninja/openwrt",
		},
		{
			name:        "default user agent",
			providerURL: "https://example.com/subscription",
			expected:    "sing-box " + C.Version,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual := providerUserAgent(testCase.providerURL, testCase.configuredUserAgent); actual != testCase.expected {
				t.Errorf("providerUserAgent() = %q, want %q", actual, testCase.expected)
			}
		})
	}
}
