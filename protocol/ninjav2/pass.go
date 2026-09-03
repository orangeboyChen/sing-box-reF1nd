package ninjav2

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	passNonceSize = 12
	passMaxFrame  = 0xffff
)

var passHKDFInfo = mustDecodeHex("d8b8c066c10e8b0d1b1ba3ad1f7de1525625d03f9d9f682f1bd6097b13a22b38")

type passConn struct {
	net.Conn
	method       Method
	masterKey    []byte
	verify       []byte
	paddingMode  string
	paddingMin   int
	paddingMax   int
	network      byte
	readAEAD     cipher.AEAD
	writeAEAD    cipher.AEAD
	readNonce    []byte
	writeNonce   []byte
	readShake    io.Reader
	writeShake   io.Reader
	readBuffer   []byte
	readMu       sync.Mutex
	writeMu      sync.Mutex
	readStarted  bool
	writeStarted bool
}

func NewPassConn(connection net.Conn, method Method, password, paddingMode string, paddingMin, paddingMax int) (net.Conn, error) {
	keyLength, err := method.KeyLen()
	if err != nil {
		return nil, err
	}
	masterKey := kdfPass([]byte(password), keyLength)
	verify, err := hkdfPass(masterKey, passHKDFInfo, []byte(password), 16)
	if err != nil {
		return nil, err
	}
	return &passConn{
		Conn: connection, method: method, masterKey: masterKey, verify: verify,
		paddingMode: paddingMode, paddingMin: paddingMin, paddingMax: paddingMax,
		network: 1,
	}, nil
}

func kdfPass(password []byte, length int) []byte {
	result := make([]byte, 0, length)
	var previous []byte
	for len(result) < length {
		hash := sha3.New512()
		_, _ = hash.Write(previous)
		_, _ = hash.Write(password)
		previous = hash.Sum(nil)
		remaining := length - len(result)
		if remaining < len(previous) {
			previous = previous[:remaining]
		}
		result = append(result, previous...)
	}
	return result
}

func hkdfPass(secret, salt, info []byte, length int) ([]byte, error) {
	result := make([]byte, length)
	_, err := io.ReadFull(hkdf.New(sha3.New512, secret, salt, info), result)
	return result, err
}

func (c *passConn) initializeWrite() ([]byte, error) {
	salt := make([]byte, passNonceSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := hkdfPass(c.masterKey, salt, passHKDFInfo, len(c.masterKey))
	if err != nil {
		return nil, err
	}
	c.writeAEAD, err = c.method.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	shake := sha3.NewShake128()
	_, _ = shake.Write(salt)
	_, _ = shake.Write(key)
	c.writeShake = shake
	c.writeNonce = append([]byte(nil), salt...)
	c.writeStarted = true
	return salt, nil
}

func (c *passConn) initializeRead() error {
	salt := make([]byte, passNonceSize)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	key, err := hkdfPass(c.masterKey, salt, passHKDFInfo, len(c.masterKey))
	if err != nil {
		return err
	}
	c.readAEAD, err = c.method.NewAEAD(key)
	if err != nil {
		return err
	}
	shake := sha3.NewShake128()
	_, _ = shake.Write(salt)
	_, _ = shake.Write(key)
	c.readShake = shake
	c.readNonce = append([]byte(nil), salt...)
	c.readStarted = true
	return nil
}

func (c *passConn) Write(payload []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	originalLength := len(payload)
	var prefix []byte
	if !c.writeStarted {
		var err error
		prefix, err = c.initializeWrite()
		if err != nil {
			return 0, err
		}
		initial := make([]byte, 0, len(c.verify)+1+len(payload))
		initial = append(initial, c.verify...)
		initial = append(initial, c.network)
		initial = append(initial, payload...)
		payload = initial
	}
	if len(payload) > passMaxFrame {
		return 0, fmt.Errorf("NinjaV2 PASS frame is too large: %d", len(payload))
	}
	paddingLength, err := c.paddingLength(len(payload))
	if err != nil {
		return 0, err
	}
	if paddingLength > passMaxFrame {
		paddingLength = passMaxFrame
	}
	body := make([]byte, len(payload)+paddingLength)
	copy(body, payload)
	if paddingLength > 0 {
		if _, err = rand.Read(body[len(payload):]); err != nil {
			return 0, err
		}
	}
	var header [4]byte
	binary.BigEndian.PutUint16(header[:2], uint16(len(payload)))
	binary.BigEndian.PutUint16(header[2:], uint16(paddingLength))
	var mask [4]byte
	if _, err = io.ReadFull(c.writeShake, mask[:]); err != nil {
		return 0, err
	}
	for index := range header {
		header[index] ^= mask[index]
	}
	headerCiphertext := c.writeAEAD.Seal(nil, c.writeNonce, header[:], nil)
	incrementNonce(c.writeNonce)
	bodyCiphertext := c.writeAEAD.Seal(nil, c.writeNonce, body, nil)
	incrementNonce(c.writeNonce)
	if err = writeAll(c.Conn, prefix, headerCiphertext, bodyCiphertext); err != nil {
		return 0, err
	}
	return originalLength, nil
}

func (c *passConn) paddingLength(payloadLength int) (int, error) {
	randomMax := c.paddingMax
	if randomMax <= 0 {
		randomMax = 128
	}
	minimum := c.paddingMin
	if minimum < 0 {
		minimum = 0
	}
	minimumPadding := minimum - payloadLength
	if minimumPadding < 0 {
		minimumPadding = 0
	}
	switch c.paddingMode {
	case "min":
		return minimumPadding, nil
	case "min_random":
		randomPadding, err := cryptoRandomInt(randomMax + 1)
		return minimumPadding + randomPadding, err
	default:
		return cryptoRandomInt(randomMax + 1)
	}
}

func cryptoRandomInt(maximum int) (int, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}

func (c *passConn) Read(buffer []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.readStarted {
		if err := c.initializeRead(); err != nil {
			return 0, err
		}
	}
	if len(c.readBuffer) == 0 {
		headerCiphertext := make([]byte, 4+c.readAEAD.Overhead())
		if _, err := io.ReadFull(c.Conn, headerCiphertext); err != nil {
			return 0, err
		}
		header, err := c.readAEAD.Open(nil, c.readNonce, headerCiphertext, nil)
		if err != nil {
			return 0, fmt.Errorf("decrypt NinjaV2 PASS header: %w", err)
		}
		incrementNonce(c.readNonce)
		var mask [4]byte
		if _, err = io.ReadFull(c.readShake, mask[:]); err != nil {
			return 0, err
		}
		for index := range header {
			header[index] ^= mask[index]
		}
		payloadLength := int(binary.BigEndian.Uint16(header[:2]))
		paddingLength := int(binary.BigEndian.Uint16(header[2:]))
		if payloadLength+paddingLength > passMaxFrame {
			return 0, fmt.Errorf("invalid NinjaV2 PASS frame length: payload=%d padding=%d", payloadLength, paddingLength)
		}
		bodyCiphertext := make([]byte, payloadLength+paddingLength+c.readAEAD.Overhead())
		if _, err = io.ReadFull(c.Conn, bodyCiphertext); err != nil {
			return 0, err
		}
		body, err := c.readAEAD.Open(nil, c.readNonce, bodyCiphertext, nil)
		if err != nil {
			return 0, fmt.Errorf("decrypt NinjaV2 PASS body: %w", err)
		}
		incrementNonce(c.readNonce)
		c.readBuffer = body[:payloadLength]
	}
	count := copy(buffer, c.readBuffer)
	c.readBuffer = c.readBuffer[count:]
	return count, nil
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}
