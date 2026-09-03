package remote

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

type subscriptionCacheStub struct {
	adapter.CacheFile
	saved *adapter.SavedBinary
}

func (c *subscriptionCacheStub) LoadSubscription(string) *adapter.SavedBinary {
	return c.saved
}

func TestProviderRemoteURLHash(t *testing.T) {
	t.Parallel()

	const providerURL = "https://example.com/provider"
	provider, err := NewProviderRemote(
		context.Background(),
		nil,
		log.NewNOPFactory(),
		"test",
		option.ProviderRemoteOptions{URL: providerURL},
	)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256([]byte(providerURL)), provider.(*ProviderRemote).urlHash)
}

func TestNewProviderRemoteRejectsMalformedURL(t *testing.T) {
	_, err := NewProviderRemote(
		context.Background(),
		nil,
		log.NewNOPFactory(),
		"test",
		option.ProviderRemoteOptions{URL: "https://[::1"},
	)
	require.Error(t, err)
}

func TestProviderRemoteClosesUnexpectedStatusBody(t *testing.T) {
	body := &trackingBody{}
	provider := &ProviderRemote{
		Adapter: providerAdapter.NewAdapter(
			context.Background(),
			nil,
			nil,
			nil,
			log.NewNOPFactory(),
			log.NewNOPFactory().NewLogger("test"),
			"test",
			C.ProviderTypeRemote,
			option.ProviderHealthCheckOptions{},
		),
		ctx:    context.Background(),
		logger: log.NewNOPFactory().NewLogger("test"),
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized", Body: body}, nil
		})},
		url: "https://example.com/provider",
	}

	require.Error(t, provider.fetch(context.Background(), false))
	require.True(t, body.closed)
}

type trackingBody struct {
	io.Reader
	closed bool
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestProviderRemoteRejectsCacheFromDifferentURL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("test")
	providerURLHash := sha256.Sum256([]byte("https://example.com/new-provider"))
	provider := &ProviderRemote{
		Adapter: providerAdapter.NewAdapter(
			ctx,
			nil,
			nil,
			nil,
			logFactory,
			logger,
			"test",
			C.ProviderTypeRemote,
			option.ProviderHealthCheckOptions{},
		),
		ctx:     ctx,
		logger:  logger,
		urlHash: providerURLHash,
		cacheFile: &subscriptionCacheStub{saved: &adapter.SavedBinary{
			Content: []byte("invalid provider content must not be parsed"),
			URLHash: []byte("different URL hash"),
		}},
	}

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.False(t, loaded)
}

func TestCachedNinjaOutboundRequiresRefetch(t *testing.T) {
	require.True(t, isNinjaProviderURL("https://example.com/222/ninja/token?tag=ninja"))
	require.True(t, cachedNinjaOutbound([]byte(`{"outbounds":[{"type":"ninja"}]}`)))
	require.False(t, cachedNinjaOutbound([]byte(`{"outbounds":[{"type":"ninjav2"}]}`)))
	require.False(t, isNinjaProviderURL("https://example.com/subscription"))
}

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
			expected:    "clash-ninja/v2.4.0",
		},
		{
			name:        "case insensitive ninja tag",
			providerURL: "https://example.com/subscription?tag=NINJA",
			expected:    "clash-ninja/v2.4.0",
		},
		{
			name:                "ninja tag takes priority over configured user agent",
			providerURL:         "https://example.com/subscription?tag=ninja",
			configuredUserAgent: "custom-agent",
			expected:            "clash-ninja/v2.4.0",
		},
		{
			name:        "ninja path",
			providerURL: "https://example.com/222/ninja/token",
			expected:    "clash-ninja/v2.4.0",
		},
		{
			name:        "case insensitive ninja path",
			providerURL: "https://example.com/222/NINJA/token",
			expected:    "clash-ninja/v2.4.0",
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
