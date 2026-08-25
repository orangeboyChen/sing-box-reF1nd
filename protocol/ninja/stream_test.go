package ninja

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/uot"
)

func TestUoTMagicDestinationAllowsZeroPort(t *testing.T) {
	for _, host := range []string{uot.MagicAddress, uot.LegacyMagicAddress} {
		if _, err := encodeTransportDestination(Destination{Host: host}); err != nil {
			t.Fatalf("encode %q: %v", host, err)
		}
	}
	if _, err := encodeTransportDestination(Destination{Host: "example.test"}); err == nil {
		t.Fatal("regular destination without port was accepted")
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
