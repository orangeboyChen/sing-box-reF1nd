package ninja

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"lukechampine.com/blake3"
)

const (
	headerSize        = 12
	authenticatorSize = aes.BlockSize
	tcpNetwork        = 1
	udpNetwork        = 2
)

type Credentials struct {
	Method       Method
	Password     string
	NodePassword string
}

type Destination struct {
	Host string
	Port uint16
}
type Header struct {
	Network       byte
	Timestamp     time.Time
	ClientSalt    []byte
	FirstDataSize uint16
}
type Session struct {
	aead  cipher.AEAD
	nonce []byte
}
type ServerResponse struct {
	ClientSalt []byte
	Timestamp  time.Time
	Payload    []byte
	Padding    int
}

func (credentials Credentials) validate() error {
	if _, err := credentials.Method.KeyLen(); err != nil {
		return err
	}
	if credentials.Password == "" || credentials.NodePassword == "" {
		return fmt.Errorf("Ninja password and node password are required")
	}
	return nil
}

func (credentials Credentials) WriteClientHandshake(writer io.Writer, destination Destination, payload []byte, paddingLength int) (*Session, error) {
	return credentials.WriteClientHandshakeNetwork(writer, tcpNetwork, destination, payload, paddingLength)
}

func (credentials Credentials) WriteClientHandshakeNetwork(writer io.Writer, network byte, destination Destination, payload []byte, paddingLength int) (*Session, error) {
	if err := credentials.validate(); err != nil {
		return nil, err
	}
	if paddingLength < 0 {
		return nil, fmt.Errorf("negative initial padding length")
	}
	encodedDestination, err := encodeTransportDestination(destination)
	if err != nil {
		return nil, err
	}
	firstDataSize := len(encodedDestination) + 2 + paddingLength + len(payload)
	if firstDataSize > 0xffff {
		return nil, fmt.Errorf("initial Ninja data is too large: %d", firstDataSize)
	}
	firstData := append([]byte{}, encodedDestination...)
	firstData = binary.BigEndian.AppendUint16(firstData, uint16(paddingLength))
	if paddingLength > 0 {
		padding := make([]byte, paddingLength)
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("generate initial padding: %w", err)
		}
		firstData = append(firstData, padding...)
	}
	firstData = append(firstData, payload...)
	keyLength, _ := credentials.Method.KeyLen()
	salt := make([]byte, keyLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate Ninja salt: %w", err)
	}
	session, authenticator, err := credentials.newSession(salt)
	if err != nil {
		return nil, err
	}
	headerCiphertext := session.seal(makeHeader(network, uint16(len(firstData))))
	firstDataCiphertext := session.seal(firstData)
	if err := writeAll(writer, salt, authenticator, headerCiphertext, firstDataCiphertext); err != nil {
		return nil, err
	}
	return session, nil
}

func (credentials Credentials) ReadClientHandshake(reader io.Reader) (*Session, Header, Destination, []byte, error) {
	if err := credentials.validate(); err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	keyLength, _ := credentials.Method.KeyLen()
	salt := make([]byte, keyLength)
	authenticator := make([]byte, authenticatorSize)
	if _, err := io.ReadFull(reader, salt); err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	if _, err := io.ReadFull(reader, authenticator); err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	session, expectedAuthenticator, err := credentials.newSession(salt)
	if err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	if !equal(authenticator, expectedAuthenticator) {
		return nil, Header{}, Destination{}, nil, fmt.Errorf("invalid Ninja authenticator")
	}
	headerCiphertext := make([]byte, headerSize+session.aead.Overhead())
	if _, err := io.ReadFull(reader, headerCiphertext); err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	headerPlaintext, err := session.open(headerCiphertext)
	if err != nil {
		return nil, Header{}, Destination{}, nil, fmt.Errorf("decrypt Ninja header: %w", err)
	}
	header, err := parseHeader(headerPlaintext)
	if err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	header.ClientSalt = append([]byte(nil), salt...)
	firstDataCiphertext := make([]byte, int(header.FirstDataSize)+session.aead.Overhead())
	if _, err := io.ReadFull(reader, firstDataCiphertext); err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	firstData, err := session.open(firstDataCiphertext)
	if err != nil {
		return nil, Header{}, Destination{}, nil, fmt.Errorf("decrypt initial Ninja data: %w", err)
	}
	destination, payload, err := decodeInitialData(firstData)
	if err != nil {
		return nil, Header{}, Destination{}, nil, err
	}
	return session, header, destination, payload, nil
}

func (credentials Credentials) WriteServerResponse(writer io.Writer, response ServerResponse) (*Session, error) {
	if _, err := credentials.Method.KeyLen(); err != nil {
		return nil, err
	}
	if credentials.Password == "" {
		return nil, fmt.Errorf("Ninja password is required")
	}
	keyLength, _ := credentials.Method.KeyLen()
	if len(response.ClientSalt) != keyLength {
		return nil, fmt.Errorf("invalid Ninja client salt length %d", len(response.ClientSalt))
	}
	if response.Padding < 0 {
		return nil, fmt.Errorf("negative Ninja response padding")
	}
	totalLength := len(response.Payload) + response.Padding
	if totalLength > 0xffff {
		return nil, fmt.Errorf("Ninja response is too large: %d", totalLength)
	}
	salt := make([]byte, keyLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate Ninja response salt: %w", err)
	}
	passwordPSK, err := credentials.Method.PSK(credentials.Password)
	if err != nil {
		return nil, err
	}
	dataKey, err := credentials.Method.SubKey(passwordPSK, salt)
	if err != nil {
		return nil, err
	}
	aead, err := credentials.Method.NewAEAD(dataKey)
	if err != nil {
		return nil, err
	}
	session := &Session{aead: aead, nonce: make([]byte, aead.NonceSize())}
	header := make([]byte, keyLength+13)
	header[0] = 1
	timestamp := response.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	putTimestamp(header[1:9], timestamp)
	copy(header[9:9+keyLength], response.ClientSalt)
	binary.BigEndian.PutUint16(header[9+keyLength:], uint16(totalLength))
	binary.BigEndian.PutUint16(header[11+keyLength:], uint16(response.Padding))
	if err := writeAll(writer, salt, session.seal(header)); err != nil {
		return nil, err
	}
	if totalLength == 0 {
		return session, nil
	}
	body := make([]byte, totalLength)
	copy(body, response.Payload)
	if response.Padding > 0 {
		if _, err := rand.Read(body[len(response.Payload):]); err != nil {
			return nil, fmt.Errorf("generate Ninja response padding: %w", err)
		}
	}
	if err := writeAll(writer, session.seal(body)); err != nil {
		return nil, err
	}
	return session, nil
}

func (credentials Credentials) ReadServerResponse(reader io.Reader, clientSalt []byte) (*Session, []byte, error) {
	if _, err := credentials.Method.KeyLen(); err != nil {
		return nil, nil, err
	}
	if credentials.Password == "" {
		return nil, nil, fmt.Errorf("Ninja password is required")
	}
	keyLength, _ := credentials.Method.KeyLen()
	if len(clientSalt) != keyLength {
		return nil, nil, fmt.Errorf("invalid Ninja client salt length %d", len(clientSalt))
	}
	responseSalt := make([]byte, keyLength)
	if _, err := io.ReadFull(reader, responseSalt); err != nil {
		return nil, nil, err
	}
	passwordPSK, err := credentials.Method.PSK(credentials.Password)
	if err != nil {
		return nil, nil, err
	}
	dataKey, err := credentials.Method.SubKey(passwordPSK, responseSalt)
	if err != nil {
		return nil, nil, err
	}
	aead, err := credentials.Method.NewAEAD(dataKey)
	if err != nil {
		return nil, nil, err
	}
	session := &Session{aead: aead, nonce: make([]byte, aead.NonceSize())}
	headerCiphertext := make([]byte, keyLength+13+session.aead.Overhead())
	if _, err := io.ReadFull(reader, headerCiphertext); err != nil {
		return nil, nil, err
	}
	header, err := session.open(headerCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt Ninja response header: %w", err)
	}
	if len(header) != keyLength+13 || header[0] != 1 {
		return nil, nil, fmt.Errorf("invalid Ninja response header")
	}
	if !equal(header[9:9+keyLength], clientSalt) {
		return nil, nil, fmt.Errorf("invalid Ninja response client salt")
	}
	totalLength := int(binary.BigEndian.Uint16(header[9+keyLength:]))
	paddingLength := int(binary.BigEndian.Uint16(header[11+keyLength:]))
	if paddingLength > totalLength {
		return nil, nil, fmt.Errorf("Ninja response padding exceeds body length: %d > %d", paddingLength, totalLength)
	}
	if totalLength == 0 {
		return session, nil, nil
	}
	bodyCiphertext := make([]byte, totalLength+session.aead.Overhead())
	if _, err := io.ReadFull(reader, bodyCiphertext); err != nil {
		return nil, nil, err
	}
	body, err := session.open(bodyCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt Ninja response body: %w", err)
	}
	return session, append([]byte(nil), body[:totalLength-paddingLength]...), nil
}

func (session *Session) WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) > 0xffff {
		return fmt.Errorf("Ninja frame is too large: %d", len(payload))
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	return writeAll(writer, session.seal(length), session.seal(payload))
}
func (session *Session) ReadFrame(reader io.Reader) ([]byte, error) {
	lengthCiphertext := make([]byte, 4+session.aead.Overhead())
	if _, err := io.ReadFull(reader, lengthCiphertext); err != nil {
		return nil, err
	}
	lengthPlaintext, err := session.open(lengthCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt Ninja frame length: %w", err)
	}
	if len(lengthPlaintext) != 4 {
		return nil, fmt.Errorf("invalid Ninja frame length block %d", len(lengthPlaintext))
	}
	totalLength := int(binary.BigEndian.Uint16(lengthPlaintext[:2]))
	paddingLength := int(binary.BigEndian.Uint16(lengthPlaintext[2:]))
	if paddingLength > totalLength {
		return nil, fmt.Errorf("Ninja padding exceeds frame length: %d > %d", paddingLength, totalLength)
	}
	payloadCiphertext := make([]byte, totalLength+session.aead.Overhead())
	if _, err := io.ReadFull(reader, payloadCiphertext); err != nil {
		return nil, err
	}
	payload, err := session.open(payloadCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt Ninja frame payload: %w", err)
	}
	return payload[:totalLength-paddingLength], nil
}
func (credentials Credentials) newSession(salt []byte) (*Session, []byte, error) {
	nodePSK, err := credentials.Method.PSK(credentials.NodePassword)
	if err != nil {
		return nil, nil, err
	}
	passwordPSK, err := credentials.Method.PSK(credentials.Password)
	if err != nil {
		return nil, nil, err
	}
	headerKey, err := credentials.Method.HeaderKey(nodePSK, salt)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(headerKey)
	if err != nil {
		return nil, nil, err
	}
	passwordSum := blake3.Sum512(passwordPSK)
	authenticator := make([]byte, block.BlockSize())
	block.Encrypt(authenticator, passwordSum[:block.BlockSize()])
	dataKey, err := credentials.Method.SubKey(passwordPSK, salt)
	if err != nil {
		return nil, nil, err
	}
	aead, err := credentials.Method.NewAEAD(dataKey)
	if err != nil {
		return nil, nil, err
	}
	return &Session{aead: aead, nonce: make([]byte, aead.NonceSize())}, authenticator, nil
}
func (session *Session) seal(plaintext []byte) []byte {
	ciphertext := session.aead.Seal(nil, session.nonce, plaintext, nil)
	incrementNonce(session.nonce)
	return ciphertext
}
func (session *Session) open(ciphertext []byte) ([]byte, error) {
	plaintext, err := session.aead.Open(nil, session.nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	incrementNonce(session.nonce)
	return plaintext, nil
}
func makeHeader(network byte, firstDataSize uint16) []byte {
	header := make([]byte, headerSize)
	header[1] = network
	putTimestamp(header[2:], time.Now())
	binary.BigEndian.PutUint16(header[10:], firstDataSize)
	return header
}

func putTimestamp(target []byte, timestamp time.Time) {
	binary.BigEndian.PutUint64(target[:8], uint64(timestamp.UnixMilli()))
}

func parseHeader(header []byte) (Header, error) {
	if len(header) != headerSize {
		return Header{}, fmt.Errorf("invalid Ninja header length %d", len(header))
	}
	milliseconds := uint64(0)
	for _, value := range header[2:10] {
		milliseconds = milliseconds<<8 | uint64(value)
	}
	return Header{Network: header[1], Timestamp: time.UnixMilli(int64(milliseconds)), FirstDataSize: binary.BigEndian.Uint16(header[10:])}, nil
}
func incrementNonce(nonce []byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			return
		}
	}
}
func writeAll(writer io.Writer, chunks ...[]byte) error {
	for _, chunk := range chunks {
		if _, err := writer.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}
func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	value := byte(0)
	for index := range left {
		value |= left[index] ^ right[index]
	}
	return value == 0
}
func encodeTransportDestination(destination Destination) ([]byte, error) {
	if destination.Host == "" || destination.Port == 0 {
		return nil, fmt.Errorf("Ninja destination host and port are required")
	}
	if address := net.ParseIP(destination.Host); address != nil {
		if ipv4 := address.To4(); ipv4 != nil {
			return appendTransportPort(append([]byte{1}, ipv4...), destination.Port), nil
		}
		return appendTransportPort(append([]byte{4}, address.To16()...), destination.Port), nil
	}
	if len(destination.Host) > 255 {
		return nil, fmt.Errorf("Ninja hostname is too long")
	}
	return appendTransportPort(append([]byte{3, byte(len(destination.Host))}, destination.Host...), destination.Port), nil
}

func decodeInitialData(data []byte) (Destination, []byte, error) {
	destination, consumed, err := decodeTransportDestination(data)
	if err != nil {
		return Destination{}, nil, err
	}
	if len(data) < consumed+2 {
		return Destination{}, nil, io.ErrUnexpectedEOF
	}
	paddingLength := int(binary.BigEndian.Uint16(data[consumed:]))
	consumed += 2
	if len(data) < consumed+paddingLength {
		return Destination{}, nil, io.ErrUnexpectedEOF
	}
	return destination, append([]byte(nil), data[consumed+paddingLength:]...), nil
}

func decodeTransportDestination(data []byte) (Destination, int, error) {
	if len(data) < 1 {
		return Destination{}, 0, io.ErrUnexpectedEOF
	}
	switch data[0] {
	case 1:
		if len(data) < 7 {
			return Destination{}, 0, io.ErrUnexpectedEOF
		}
		return Destination{Host: net.IP(data[1:5]).String(), Port: binary.BigEndian.Uint16(data[5:7])}, 7, nil
	case 3:
		if len(data) < 2 {
			return Destination{}, 0, io.ErrUnexpectedEOF
		}
		hostLength := int(data[1])
		if len(data) < 2+hostLength+2 {
			return Destination{}, 0, io.ErrUnexpectedEOF
		}
		return Destination{Host: string(data[2 : 2+hostLength]), Port: binary.BigEndian.Uint16(data[2+hostLength:])}, 2 + hostLength + 2, nil
	case 4:
		if len(data) < 19 {
			return Destination{}, 0, io.ErrUnexpectedEOF
		}
		return Destination{Host: net.IP(data[1:17]).String(), Port: binary.BigEndian.Uint16(data[17:19])}, 19, nil
	default:
		return Destination{}, 0, fmt.Errorf("unsupported Ninja address type %d", data[0])
	}
}
func appendTransportPort(data []byte, port uint16) []byte {
	return append(data, byte(port>>8), byte(port))
}
