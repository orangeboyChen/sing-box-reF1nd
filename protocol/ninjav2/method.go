package ninjav2

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

const (
	pskContext    = "de6dbaddc4e0dbaaeb65778b44e6fdac"
	subKeyContext = "52386811679ea908c4a2b02f367c472c"
	headerContext = "e14d197ae519bdd2d9a75ae94df7e208"
)

type Method string

const (
	AES128GCM        Method = "aes-128-gcm"
	AES192GCM        Method = "aes-192-gcm"
	AES256GCM        Method = "aes-256-gcm"
	ChaCha20Poly1305 Method = "chacha20-ietf-poly1305"
)

func ParseMethod(value string) (Method, error) {
	method := Method(value)
	if _, err := method.KeyLen(); err != nil {
		return "", err
	}
	return method, nil
}

func (method Method) KeyLen() (int, error) {
	switch method {
	case AES128GCM:
		return 16, nil
	case AES192GCM:
		return 24, nil
	case AES256GCM, ChaCha20Poly1305:
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported Ninja method %q", method)
	}
}

func (method Method) PSK(password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("empty password")
	}
	keyLength, err := method.KeyLen()
	if err != nil {
		return nil, err
	}
	key := make([]byte, keyLength)
	blake3.DeriveKey(key, pskContext, []byte(password))
	return key, nil
}

func (method Method) SubKey(key, material []byte) ([]byte, error) {
	return method.derive(subKeyContext, key, material)
}

func (method Method) HeaderKey(key, material []byte) ([]byte, error) {
	return method.derive(headerContext, key, material)
}

func (method Method) derive(context string, key, material []byte) ([]byte, error) {
	keyLength, err := method.KeyLen()
	if err != nil {
		return nil, err
	}
	derived := make([]byte, keyLength)
	input := make([]byte, 0, len(key)+len(material))
	input = append(input, key...)
	input = append(input, material...)
	blake3.DeriveKey(derived, context, input)
	return derived, nil
}

func (method Method) NewAEAD(key []byte) (cipher.AEAD, error) {
	keyLength, err := method.KeyLen()
	if err != nil {
		return nil, err
	}
	if len(key) != keyLength {
		return nil, fmt.Errorf("invalid %s key length %d", method, len(key))
	}
	if method == ChaCha20Poly1305 {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
