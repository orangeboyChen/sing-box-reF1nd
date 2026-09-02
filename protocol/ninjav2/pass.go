package ninjav2

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	passNonceSize = 12
	passMaxFrame  = 0xffff
)

type passConn struct {
	net.Conn
	readAEAD, writeAEAD   cipher.AEAD
	readNonce, writeNonce []byte
	readShake, writeShake io.Reader
	firstHeader           []byte
	firstWrite            bool
	readBuf               []byte
	writeMu               sync.Mutex
	master                []byte
	method                Method
	keyLength             int
	destination           Destination
	sendMaterial          []byte
	materialSent          bool
	materialRead          bool
}

func NewPassConn(connection net.Conn, method Method, password, nodePassword, passInfo string, version int, destination Destination) (net.Conn, error) {
	keyLength, err := method.KeyLen()
	if err != nil {
		return nil, err
	}
	info, err := decodePassInfo(passInfo)
	if err != nil {
		return nil, fmt.Errorf("decode NinjaV2 PASS-INFO: %w", err)
	}
	if version == 0 {
		version = 1
	}
	masterHash := sha3.Sum512([]byte(passInfo))
	master := masterHash[:]
	sendMaterial := make([]byte, 12)
	if _, err = rand.Read(sendMaterial); err != nil {
		return nil, err
	}
	recvMaterial := make([]byte, 12)
	readKey, err := passExpandMaterial(master, recvMaterial, "recvAEAD", keyLength)
	if err != nil {
		return nil, err
	}
	writeKey, err := passExpandMaterial(master, sendMaterial, "sendAEAD", keyLength)
	if err != nil {
		return nil, err
	}
	readAEAD, err := method.NewAEAD(readKey)
	if err != nil {
		return nil, err
	}
	writeAEAD, err := method.NewAEAD(writeKey)
	if err != nil {
		return nil, err
	}
	readMask, err := passExpandMaterial(master, recvMaterial, "readShake", 32)
	if err != nil {
		return nil, err
	}
	writeMask, err := passExpandMaterial(master, sendMaterial, "writeShake", 32)
	if err != nil {
		return nil, err
	}
	readShake, writeShake := sha3.NewShake256(), sha3.NewShake256()
	_, _ = readShake.Write(readMask)
	_, _ = writeShake.Write(writeMask)
	firstHeader := make([]byte, 18)
	copy(firstHeader, info)
	firstHeader[16] = 3
	if len(info) > 0x19 {
		firstHeader[17] = info[0x19]
	}
	return &passConn{
		Conn:        connection,
		readAEAD:    readAEAD,
		writeAEAD:   writeAEAD,
		readNonce:   make([]byte, passNonceSize),
		writeNonce:  make([]byte, passNonceSize),
		readShake:   readShake,
		writeShake:  writeShake,
		firstHeader: firstHeader,
		master:      master, method: method, keyLength: keyLength, sendMaterial: sendMaterial, destination: destination,
	}, nil
}

func passExpand(secret []byte, label string, length int) ([]byte, error) {
	result := make([]byte, length)
	_, err := io.ReadFull(hkdf.New(sha3.New512, secret, nil, []byte(label)), result)
	return result, err
}

func passExpandMaterial(secret, material []byte, label string, length int) ([]byte, error) {
	result := make([]byte, length)
	_, err := io.ReadFull(hkdf.New(sha3.New512, secret, material, []byte(label)), result)
	return result, err
}

func decodePassInfo(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func (c *passConn) Write(payload []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	originalLength := len(payload)
	if !c.firstWrite {
		destination, err := encodeTransportDestination(c.destination)
		if err != nil {
			return 0, err
		}
		initial := make([]byte, 0, len(destination)+len(payload))
		initial = append(initial, destination...)
		initial = append(initial, payload...)
		if len(initial)+len(c.firstHeader) > passMaxFrame {
			return 0, fmt.Errorf("NinjaV2 PASS frame is too large: %d", len(payload)+len(c.firstHeader))
		}
		wrapped := make([]byte, 0, len(c.firstHeader)+len(initial))
		wrapped = append(wrapped, c.firstHeader...)
		wrapped = append(wrapped, initial...)
		payload = wrapped
		c.firstWrite = true
	}
	if !c.materialSent {
		if err := writeAll(c.Conn, c.sendMaterial); err != nil {
			return 0, err
		}
		c.materialSent = true
	}
	if len(payload) > passMaxFrame {
		return 0, fmt.Errorf("NinjaV2 PASS frame is too large: %d", len(payload))
	}
	paddingLength := 0
	if remaining := passMaxFrame - len(payload); remaining > 0 {
		var randomByte [1]byte
		if _, err := rand.Read(randomByte[:]); err != nil {
			return 0, err
		}
		paddingLength = int(randomByte[0]) % 0x81
		if paddingLength > remaining {
			paddingLength = remaining
		}
	}
	body := make([]byte, len(payload)+paddingLength)
	copy(body, payload)
	if paddingLength != 0 {
		if _, err := rand.Read(body[len(payload):]); err != nil {
			return 0, err
		}
	}
	var header [4]byte
	binary.BigEndian.PutUint16(header[:2], uint16(len(payload)))
	binary.BigEndian.PutUint16(header[2:], uint16(paddingLength))
	var mask [4]byte
	if _, err := io.ReadFull(c.writeShake, mask[:]); err != nil {
		return 0, err
	}
	// The binary reads two big-endian words independently from the shake
	// stream, reverses them, XORs the fields, then reverses back. This is
	// equivalent to XORing each network-order field with its corresponding
	// two shake bytes.
	for i := 0; i < 4; i++ {
		header[i] ^= mask[i]
	}
	headerCiphertext := c.writeAEAD.Seal(nil, c.writeNonce, header[:], nil)
	incrementNonce(c.writeNonce)
	bodyCiphertext := c.writeAEAD.Seal(nil, c.writeNonce, body, nil)
	incrementNonce(c.writeNonce)
	if err := writeAll(c.Conn, headerCiphertext, bodyCiphertext); err != nil {
		return 0, err
	}
	return originalLength, nil
}

func (c *passConn) Read(buffer []byte) (int, error) {
	if !c.materialRead {
		material := make([]byte, passNonceSize)
		if _, err := io.ReadFull(c.Conn, material); err != nil {
			return 0, err
		}
		key, err := passExpandMaterial(c.master, material, "recvAEAD", c.keyLength)
		if err != nil {
			return 0, err
		}
		c.readAEAD, err = c.method.NewAEAD(key)
		if err != nil {
			return 0, err
		}
		mask, err := passExpandMaterial(c.master, material, "readShake", 32)
		if err != nil {
			return 0, err
		}
		shake := sha3.NewShake256()
		_, _ = shake.Write(mask)
		c.readShake = shake
		c.materialRead = true
	}
	if len(c.readBuf) == 0 {
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
		for i := 0; i < 2; i++ {
			header[i] ^= mask[i]
			header[i+2] ^= mask[i+2]
		}
		payloadLength, paddingLength := int(binary.BigEndian.Uint16(header[:2])), int(binary.BigEndian.Uint16(header[2:]))
		if payloadLength+paddingLength > passMaxFrame {
			return 0, fmt.Errorf("invalid NinjaV2 PASS frame length")
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
		c.readBuf = append(c.readBuf, body[:payloadLength]...)
	}
	count := copy(buffer, c.readBuf)
	c.readBuf = c.readBuf[count:]
	return count, nil
}
