package ninjav2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type passInfo struct {
	Set struct {
		Network        string `json:"network"`
		Pass           bool   `json:"pass"`
		ServerName     string `json:"servername"`
		SkipCertVerify bool   `json:"skip-cert-verify"`
		TLS            bool   `json:"tls"`
		PassOptions    struct {
			Method           string `json:"method"`
			PaddingMin       int    `json:"padding_min"`
			PaddingMode      string `json:"padding_mode"`
			PaddingRandomMax int    `json:"padding_random_max"`
			Password         string `json:"password"`
		} `json:"pass-opts"`
		WebsocketOptions struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
		} `json:"ws-opts"`
	} `json:"set"`
	Replace []struct {
		Match struct {
			Server string `json:"server"`
		} `json:"match"`
		Replace struct {
			Server string `json:"server"`
		} `json:"replace"`
	} `json:"replace"`
}

func decodePassInfo(value string, version int) (*passInfo, error) {
	var versionKey string
	switch version {
	case 0, 1:
		versionKey = "ninja-pass-info"
	case 2:
		versionKey = "ninja-pass2-info"
	case 3:
		versionKey = "ninja-pass3-info"
	default:
		return nil, fmt.Errorf("unsupported NinjaV2 PASS-INFO version %d", version)
	}
	var decoded []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err = encoding.DecodeString(value)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	digest := sha256.Sum256([]byte(versionKey))
	for index := range decoded {
		decoded[index] ^= digest[index%len(digest)]
	}
	var info passInfo
	if err = json.Unmarshal(decoded, &info); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	return &info, nil
}

func (i *passInfo) replaceServer(server string) string {
	for _, replacement := range i.Replace {
		if replacement.Match.Server == server && replacement.Replace.Server != "" {
			return replacement.Replace.Server
		}
	}
	return server
}
