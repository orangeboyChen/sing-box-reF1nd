package ninja

import (
	"bytes"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestRejectsDestinationWithoutPort(t *testing.T) {
	if _, err := encodeTransportDestination(Destination{Host: "example.test"}); err == nil {
		t.Fatal("regular destination without port was accepted")
	}
}

func TestUDPHandshakeUsesNativeNetwork(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "test-password", NodePassword: "test-node-password"}
	var wire bytes.Buffer
	if _, err := credentials.WriteClientHandshakeNetwork(&wire, udpNetwork, Destination{Host: "1.1.1.1", Port: 53}, []byte("payload"), 1); err != nil {
		t.Fatal(err)
	}
	_, header, destination, payload, err := credentials.ReadClientHandshake(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if header.Network != udpNetwork || destination != (Destination{Host: "1.1.1.1", Port: 53}) || !bytes.Equal(payload, []byte("payload")) {
		t.Fatalf("unexpected UDP handshake: network=%d destination=%v payload=%q", header.Network, destination, payload)
	}
}

func TestUDPResponseStripsDestination(t *testing.T) {
	connection := &conn{
		buffer:        append([]byte{1, 1, 1, 1, 1, 0, 53}, []byte("dns-payload")...),
		handshakeDone: make(chan struct{}),
		readSession:   &Session{},
		writeSession:  &Session{},
		credentials:   Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"},
	}
	close(connection.handshakeDone)
	packet := &packetConn{conn: connection, destination: M.ParseSocksaddr("1.1.1.1:53")}
	buffer := make([]byte, 32)
	count, address, err := packet.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if count != len("dns-payload") || !bytes.Equal(buffer[:count], []byte("dns-payload")) {
		t.Fatalf("unexpected UDP payload: %q", buffer[:count])
	}
	if address.String() != "1.1.1.1:53" {
		t.Fatalf("unexpected UDP address: %v", address)
	}
}

func TestUDPStreamResponseStripsDestination(t *testing.T) {
	connection := &conn{
		buffer:        append([]byte{1, 1, 1, 1, 1, 0, 53}, []byte("dns-payload")...),
		handshakeDone: make(chan struct{}),
		readSession:   &Session{},
		writeSession:  &Session{},
		network:       udpNetwork,
	}
	close(connection.handshakeDone)
	buffer := make([]byte, 32)
	count, err := connection.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if count != len("dns-payload") || !bytes.Equal(buffer[:count], []byte("dns-payload")) {
		t.Fatalf("unexpected UDP stream payload: %q", buffer[:count])
	}
}

func TestHandshakeAndFramesRoundTrip(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "test-password", NodePassword: "test-node-password"}
	destination := Destination{Host: "example.test", Port: 443}
	var wire bytes.Buffer
	writer, err := credentials.WriteClientHandshake(&wire, destination, []byte("initial payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.WriteFrame(&wire, []byte("later frame")); err != nil {
		t.Fatal(err)
	}
	reader, header, decodedDestination, initialPayload, err := credentials.ReadClientHandshake(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if header.Network != tcpNetwork || decodedDestination != destination || !bytes.Equal(initialPayload, []byte("initial payload")) {
		t.Fatal("client handshake mismatch")
	}
	frame, err := reader.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, []byte("later frame")) {
		t.Fatal("frame mismatch")
	}
}

func TestReadStartsHandshake(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	client := NewClientConn(clientRaw, credentials, Destination{Host: "example.test", Port: 443})
	serverDone := make(chan error, 1)
	go func() {
		_, header, _, _, err := credentials.ReadClientHandshake(serverRaw)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = credentials.WriteServerResponse(serverRaw, ServerResponse{ClientSalt: header.ClientSalt, Payload: []byte("greeting")})
		serverDone <- err
	}()
	buffer := make([]byte, 32)
	count, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:count], []byte("greeting")) {
		t.Fatalf("unexpected greeting: %q", buffer[:count])
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestLargeTCPWriteSplitsNinjaFrames(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	client := NewClientConn(clientRaw, credentials, Destination{Host: "example.test", Port: 443})
	payload := bytes.Repeat([]byte("x"), 0xffff+1024)
	writeResult := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		count, err := client.Write(payload)
		writeResult <- struct {
			count int
			err   error
		}{count, err}
	}()
	reader, _, _, initial, err := credentials.ReadClientHandshake(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial) != 0 {
		t.Fatalf("unexpected initial payload length: %d", len(initial))
	}
	received := make([]byte, 0, len(payload))
	for len(received) < len(payload) {
		frame, readErr := reader.ReadFrame(serverRaw)
		if readErr != nil {
			t.Fatal(readErr)
		}
		received = append(received, frame...)
	}
	result := <-writeResult
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.count != len(payload) || !bytes.Equal(received, payload) {
		t.Fatalf("large write mismatch: count=%d payload=%d received=%d", result.count, len(payload), len(received))
	}
}

func TestRejectsInvalidAuthenticator(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "test-password", NodePassword: "test-node-password"}
	var wire bytes.Buffer
	if _, err := credentials.WriteClientHandshake(&wire, Destination{Host: "example.test", Port: 443}, nil, 0); err != nil {
		t.Fatal(err)
	}
	data := wire.Bytes()
	data[16] ^= 1
	if _, _, _, _, err := credentials.ReadClientHandshake(bytes.NewReader(data)); err == nil {
		t.Fatal("ReadClientHandshake accepted a modified authenticator")
	}
}

func TestAllMethodsHandshakeRoundTrip(t *testing.T) {
	for _, method := range []Method{AES128GCM, AES192GCM, AES256GCM, ChaCha20Poly1305} {
		t.Run(string(method), func(t *testing.T) {
			credentials := Credentials{Method: method, Password: "test-password", NodePassword: "test-node-password"}
			var wire bytes.Buffer
			if _, err := credentials.WriteClientHandshake(&wire, Destination{Host: "example.test", Port: 443}, []byte("payload"), 0); err != nil {
				t.Fatal(err)
			}
			if _, _, _, payload, err := credentials.ReadClientHandshake(&wire); err != nil || !bytes.Equal(payload, []byte("payload")) {
				t.Fatalf("round trip failed: payload=%q err=%v", payload, err)
			}
		})
	}
}

func TestServerResponseRoundTrip(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "test-password", NodePassword: "test-node-password"}
	var clientWire bytes.Buffer
	if _, err := credentials.WriteClientHandshake(&clientWire, Destination{Host: "example.test", Port: 443}, nil, 0); err != nil {
		t.Fatal(err)
	}
	_, header, _, _, err := credentials.ReadClientHandshake(&clientWire)
	if err != nil {
		t.Fatal(err)
	}
	var responseWire bytes.Buffer
	if _, err = credentials.WriteServerResponse(&responseWire, ServerResponse{ClientSalt: header.ClientSalt, Payload: []byte("response payload"), Padding: 5}); err != nil {
		t.Fatal(err)
	}
	_, response, err := credentials.ReadServerResponse(&responseWire, header.ClientSalt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte("response payload")) {
		t.Fatal("response mismatch")
	}
}

func TestInitialPaddingIsExcludedFromPayload(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "test-password", NodePassword: "test-node-password"}
	var wire bytes.Buffer
	if _, err := credentials.WriteClientHandshake(&wire, Destination{Host: "example.test", Port: 443}, []byte("payload"), 32); err != nil {
		t.Fatal(err)
	}
	_, _, _, payload, err := credentials.ReadClientHandshake(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("payload")) {
		t.Fatalf("unexpected payload: %q", payload)
	}
}
