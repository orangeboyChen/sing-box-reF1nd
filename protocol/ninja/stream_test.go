package ninja

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type countingWriteConn struct {
	net.Conn
	writeCount atomic.Int32
}

func (c *countingWriteConn) Write(payload []byte) (int, error) {
	c.writeCount.Add(1)
	return c.Conn.Write(payload)
}

type delayedTimeoutConn struct {
	net.Conn
	release  <-chan struct{}
	returned chan<- struct{}
}

func (c *delayedTimeoutConn) Read(payload []byte) (int, error) {
	count, err := c.Conn.Read(payload)
	if timeoutError, loaded := err.(net.Error); loaded && timeoutError.Timeout() {
		<-c.release
		close(c.returned)
	}
	return count, err
}

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

func TestUDPFirstWriteIsCoalesced(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	recorder := &countingWriteConn{Conn: clientRaw}
	destination := M.ParseSocksaddr("stun.example.test:3478")
	client := NewClientPacketConn(recorder, credentials, destination)
	payload := []byte("udp-first-payload")
	writeResult := make(chan error, 1)
	go func() {
		_, err := client.WriteTo(payload, nil)
		writeResult <- err
	}()

	_, header, decodedDestination, initialPayload, err := credentials.ReadClientHandshake(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-writeResult; err != nil {
		t.Fatal(err)
	}
	if recorder.writeCount.Load() != 1 {
		t.Fatalf("expected one UDP transport write, got %d", recorder.writeCount.Load())
	}
	if header.Network != udpNetwork || decodedDestination != (Destination{Host: "stun.example.test", Port: 3478}) {
		t.Fatalf("unexpected UDP handshake: network=%d destination=%v", header.Network, decodedDestination)
	}
	if !bytes.Equal(initialPayload, payload) {
		t.Fatalf("unexpected UDP initial payload: %q", initialPayload)
	}
	encodedDestination, err := encodeTransportDestination(decodedDestination)
	if err != nil {
		t.Fatal(err)
	}
	paddingLength := int(header.FirstDataSize) - len(encodedDestination) - 2 - len(payload)
	paddingLimit := firstBlockTarget - len(encodedDestination) - len(payload)
	if paddingLimit > firstBlockMaxPad {
		paddingLimit = firstBlockMaxPad
	}
	if paddingLength < 1 || paddingLength > paddingLimit {
		t.Fatalf("unexpected UDP initial padding: %d (limit %d)", paddingLength, paddingLimit)
	}
}

func TestUDPWritePreservesBoundDomainDestination(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	destination := M.ParseSocksaddr("stun.example.test:3478")
	client := NewClientPacketConn(clientRaw, credentials, destination)
	payload := []byte("udp-payload")
	writeResult := make(chan error, 1)
	go func() {
		_, err := client.WriteTo(payload, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 3478})
		writeResult <- err
	}()

	_, header, decodedDestination, initialPayload, err := credentials.ReadClientHandshake(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-writeResult; err != nil {
		t.Fatal(err)
	}
	if header.Network != udpNetwork || decodedDestination != (Destination{Host: "stun.example.test", Port: 3478}) {
		t.Fatalf("unexpected UDP handshake: network=%d destination=%v", header.Network, decodedDestination)
	}
	if !bytes.Equal(initialPayload, payload) {
		t.Fatalf("unexpected UDP initial payload: %q", initialPayload)
	}
}

func TestDNSWritePreservesBoundDomainDestination(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	destination := M.ParseSocksaddr("dns.example.test:53")
	serverResult := make(chan error, 1)
	client, err := NewClientPacketConnWithDialer(context.Background(), func(context.Context) (net.Conn, error) {
		clientRaw, serverRaw := net.Pipe()
		go func() {
			defer serverRaw.Close()
			_, _, decodedDestination, payload, readErr := credentials.ReadClientHandshake(serverRaw)
			if readErr == nil && decodedDestination != (Destination{Host: "dns.example.test", Port: 53}) {
				readErr = errors.New("DNS handshake did not preserve the bound domain destination")
			}
			if readErr == nil && !bytes.Equal(payload, []byte("dns-query")) {
				readErr = errors.New("DNS handshake did not preserve the query payload")
			}
			serverResult <- readErr
		}()
		return clientRaw, nil
	}, credentials, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.WriteTo([]byte("dns-query"), &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53}); err != nil {
		t.Fatal(err)
	}
	if err = <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestUDPClientConnUsesStreamPerDNSQuery(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	destination := M.ParseSocksaddr("dns.example.test:53")
	var dialCount atomic.Int32
	serverErrors := make(chan error, 2)
	dialer := func(context.Context) (net.Conn, error) {
		clientRaw, serverRaw := net.Pipe()
		dialCount.Add(1)
		go func() {
			defer serverRaw.Close()
			_, header, decodedDestination, payload, err := credentials.ReadClientHandshake(serverRaw)
			if err == nil && decodedDestination != (Destination{Host: "dns.example.test", Port: 53}) {
				err = errors.New("DNS handshake did not preserve the bound domain destination")
			}
			var encodedDestination []byte
			if err == nil {
				encodedDestination, err = encodeTransportDestination(decodedDestination)
			}
			if err == nil {
				response := append(encodedDestination, payload...)
				_, err = credentials.WriteServerResponse(serverRaw, ServerResponse{ClientSalt: header.ClientSalt, Payload: response})
			}
			serverErrors <- err
		}()
		return clientRaw, nil
	}
	client, err := NewClientUDPConnWithDialer(context.Background(), dialer, credentials, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.RemoteAddr().String() != destination.String() {
		t.Fatalf("connected UDP remote address lost its domain: %v", client.RemoteAddr())
	}

	payloads := [][]byte{[]byte("query-a"), []byte("query-aaaa")}
	writeErrors := make(chan error, len(payloads))
	for _, payload := range payloads {
		go func() {
			count, writeErr := client.Write(payload)
			if writeErr == nil && count != len(payload) {
				writeErr = errors.New("unexpected write count")
			}
			writeErrors <- writeErr
		}()
	}
	for range payloads {
		if err = <-writeErrors; err != nil {
			t.Fatal(err)
		}
	}

	responses := make(map[string]bool)
	for range payloads {
		buffer := make([]byte, 64)
		count, readErr := client.Read(buffer)
		if readErr != nil {
			t.Fatal(readErr)
		}
		responses[string(buffer[:count])] = true
	}
	if !responses["query-a"] || !responses["query-aaaa"] {
		t.Fatalf("unexpected responses: %v", responses)
	}
	if dialCount.Load() != int32(len(payloads)) {
		t.Fatalf("expected one Ninja stream per DNS query, got %d streams", dialCount.Load())
	}
	for range payloads {
		if err = <-serverErrors; err != nil {
			t.Fatal(err)
		}
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

func TestUDPReadWaitsForInitialWrite(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	client := NewClientPacketConn(clientRaw, credentials, M.ParseSocksaddr("1.1.1.1:53"))

	type readResult struct {
		payload []byte
		err     error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, 64)
		count, _, err := client.ReadFrom(buffer)
		readDone <- readResult{payload: append([]byte(nil), buffer[:count]...), err: err}
	}()

	if err := serverRaw.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var firstByte [1]byte
	if _, err := serverRaw.Read(firstByte[:]); err == nil {
		t.Fatal("UDP read sent an empty handshake before the first packet")
	} else if timeoutError, loaded := err.(net.Error); !loaded || !timeoutError.Timeout() {
		t.Fatalf("unexpected pre-write read error: %v", err)
	}
	if err := serverRaw.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	payload := []byte("dns-query")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.WriteTo(payload, nil)
		writeDone <- err
	}()

	_, header, _, initialPayload, err := credentials.ReadClientHandshake(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initialPayload, payload) {
		t.Fatalf("UDP packet was not carried by the initial handshake: %q", initialPayload)
	}
	response := append([]byte{1, 1, 1, 1, 1, 0, 53}, []byte("dns-response")...)
	if _, err = credentials.WriteServerResponse(serverRaw, ServerResponse{ClientSalt: header.ClientSalt, Payload: response}); err != nil {
		t.Fatal(err)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
	result := <-readDone
	if result.err != nil {
		t.Fatal(result.err)
	}
	if !bytes.Equal(result.payload, []byte("dns-response")) {
		t.Fatalf("unexpected UDP response: %q", result.payload)
	}
}

func TestUDPReadWaitsForInitialWriteDeadline(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	client := NewClientPacketConn(clientRaw, credentials, M.ParseSocksaddr("1.1.1.1:53"))

	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		_, _, err := client.ReadFrom(buffer)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unexpected read error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP read did not honor its deadline while waiting for the first write")
	}

	if err := serverRaw.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var firstByte [1]byte
	if _, err := serverRaw.Read(firstByte[:]); err == nil {
		t.Fatal("deadline wait sent an empty UDP handshake")
	} else if timeoutError, loaded := err.(net.Error); !loaded || !timeoutError.Timeout() {
		t.Fatalf("unexpected server read error: %v", err)
	}
}

func TestUDPClientPacketConnUsesStreamPerPacketOutsideDNS(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	destination := M.ParseSocksaddr("stun.example.test:3478")
	var dialCount atomic.Int32
	serverErrors := make(chan error, 2)
	dialer := func(context.Context) (net.Conn, error) {
		clientRaw, serverRaw := net.Pipe()
		dialCount.Add(1)
		go func() {
			defer serverRaw.Close()
			_, header, _, payload, err := credentials.ReadClientHandshake(serverRaw)
			if err != nil {
				serverErrors <- err
				return
			}
			encodedDestination, encodeErr := encodeTransportDestination(toDestination(destination))
			if encodeErr != nil {
				serverErrors <- encodeErr
				return
			}
			response := append(encodedDestination, payload...)
			_, err = credentials.WriteServerResponse(serverRaw, ServerResponse{ClientSalt: header.ClientSalt, Payload: response})
			serverErrors <- err
		}()
		return clientRaw, nil
	}
	client, err := NewClientPacketConnWithDialer(context.Background(), dialer, credentials, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	writeErrors := make(chan error, 2)
	for _, payload := range [][]byte{[]byte("first-query"), []byte("second-query")} {
		go func() {
			count, err := client.WriteTo(payload, nil)
			if err == nil && count != len(payload) {
				err = errors.New("unexpected write count")
			}
			writeErrors <- err
		}()
	}
	for range 2 {
		if err := <-writeErrors; err != nil {
			t.Fatal(err)
		}
	}

	responses := make(map[string]bool)
	for range 2 {
		buffer := make([]byte, 64)
		count, address, err := client.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if address.String() != destination.String() {
			t.Fatalf("unexpected response address: %v", address)
		}
		responses[string(buffer[:count])] = true
	}
	if !responses["first-query"] || !responses["second-query"] {
		t.Fatalf("unexpected responses: %v", responses)
	}
	if dialCount.Load() != 2 {
		t.Fatalf("expected one Ninja stream per packet, got %d streams", dialCount.Load())
	}
	for range 2 {
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
}

func TestUDPClientPacketConnOutlivesDialContext(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	destination := M.ParseSocksaddr("1.1.1.1:53")
	ctx, cancel := context.WithCancel(context.Background())
	serverErrors := make(chan error, 1)
	client, err := NewClientPacketConnWithDialer(ctx, func(dialCtx context.Context) (net.Conn, error) {
		if err := dialCtx.Err(); err != nil {
			return nil, err
		}
		clientRaw, serverRaw := net.Pipe()
		go func() {
			defer serverRaw.Close()
			_, header, _, payload, err := credentials.ReadClientHandshake(serverRaw)
			if err == nil {
				response := append([]byte{1, 1, 1, 1, 1, 0, 53}, payload...)
				_, err = credentials.WriteServerResponse(serverRaw, ServerResponse{ClientSalt: header.ClientSalt, Payload: response})
			}
			serverErrors <- err
		}()
		return clientRaw, nil
	}, credentials, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cancel()
	if _, err = client.WriteTo([]byte("query"), nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	count, _, err := client.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:count], []byte("query")) {
		t.Fatalf("unexpected response: %q", buffer[:count])
	}
	if err = <-serverErrors; err != nil {
		t.Fatal(err)
	}
}

func TestUDPClientPacketConnReadDeadlineClosesStream(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	destination := M.ParseSocksaddr("1.1.1.1:53")
	serverClosed := make(chan error, 1)
	client, err := NewClientPacketConnWithDialer(context.Background(), func(context.Context) (net.Conn, error) {
		clientRaw, serverRaw := net.Pipe()
		go func() {
			defer serverRaw.Close()
			if _, _, _, _, err := credentials.ReadClientHandshake(serverRaw); err != nil {
				serverClosed <- err
				return
			}
			var buffer [1]byte
			_, err := serverRaw.Read(buffer[:])
			serverClosed <- err
		}()
		return clientRaw, nil
	}, credentials, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = client.WriteTo([]byte("query"), nil); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if _, _, err = client.ReadFrom(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unexpected read error: %v", err)
	}
	select {
	case err = <-serverClosed:
		if err == nil {
			t.Fatal("server stream remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not close the one-shot stream")
	}
}

func TestUDPClientPacketConnDoesNotQueueStaleTimeout(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	destination := M.ParseSocksaddr("stun.example.test:3478")
	firstTimeoutRelease := make(chan struct{})
	firstTimeoutReturned := make(chan struct{})
	secondResponseRelease := make(chan struct{})
	serverErrors := make(chan error, 2)
	var dialCount atomic.Int32
	client, err := NewClientPacketConnWithDialer(context.Background(), func(context.Context) (net.Conn, error) {
		clientRaw, serverRaw := net.Pipe()
		dialIndex := dialCount.Add(1)
		go func() {
			defer serverRaw.Close()
			_, header, decodedDestination, payload, readErr := credentials.ReadClientHandshake(serverRaw)
			if readErr == nil && decodedDestination != toDestination(destination) {
				readErr = errors.New("unexpected UDP destination")
			}
			if dialIndex == 1 {
				serverErrors <- readErr
				if readErr == nil {
					var buffer [1]byte
					_, _ = serverRaw.Read(buffer[:])
				}
				return
			}
			if readErr == nil {
				<-secondResponseRelease
				var encodedDestination []byte
				encodedDestination, readErr = encodeTransportDestination(decodedDestination)
				if readErr == nil {
					response := append(encodedDestination, payload...)
					_, readErr = credentials.WriteServerResponse(serverRaw, ServerResponse{ClientSalt: header.ClientSalt, Payload: response})
				}
			}
			serverErrors <- readErr
		}()
		if dialIndex == 1 {
			return &delayedTimeoutConn{Conn: clientRaw, release: firstTimeoutRelease, returned: firstTimeoutReturned}, nil
		}
		return clientRaw, nil
	}, credentials, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	oneShotClient := client.(*oneShotPacketConn)

	if err = client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = client.WriteTo([]byte("first"), destination); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, _, err = client.ReadFrom(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unexpected first read error: %v", err)
	}

	if err = client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = client.WriteTo([]byte("second"), destination); err != nil {
		t.Fatal(err)
	}
	close(firstTimeoutRelease)
	select {
	case <-firstTimeoutReturned:
	case <-time.After(time.Second):
		t.Fatal("first stream did not return its delayed timeout")
	}
	deadline := time.Now().Add(time.Second)
	for {
		oneShotClient.access.Lock()
		connectionCount := len(oneShotClient.connections)
		oneShotClient.access.Unlock()
		if connectionCount == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired stream was not removed")
		}
		time.Sleep(time.Millisecond)
	}
	if resultCount := len(oneShotClient.results); resultCount != 0 {
		t.Fatalf("expired stream queued %d stale result(s)", resultCount)
	}

	close(secondResponseRelease)
	count, _, err := client.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:count], []byte("second")) {
		t.Fatalf("unexpected retry response: %q", buffer[:count])
	}
	for range 2 {
		if err = <-serverErrors; err != nil {
			t.Fatal(err)
		}
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
	if len(initial) == 0 || len(initial) > firstBlockTarget {
		t.Fatalf("unexpected initial payload length: %d", len(initial))
	}
	received := append(make([]byte, 0, len(payload)), initial...)
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

func TestTCPFirstWriteIsCoalesced(t *testing.T) {
	credentials := Credentials{Method: AES128GCM, Password: "password", NodePassword: "node-password"}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	recorder := &countingWriteConn{Conn: clientRaw}
	client := NewClientConn(recorder, credentials, Destination{Host: "example.test", Port: 443})
	payload := bytes.Repeat([]byte("x"), 2048)
	writeResult := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeResult <- err
	}()
	reader, _, _, initial, err := credentials.ReadClientHandshake(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	received := append(make([]byte, 0, len(payload)), initial...)
	for len(received) < len(payload) {
		frame, readErr := reader.ReadFrame(serverRaw)
		if readErr != nil {
			t.Fatal(readErr)
		}
		received = append(received, frame...)
	}
	if err = <-writeResult; err != nil {
		t.Fatal(err)
	}
	if recorder.writeCount.Load() != 1 {
		t.Fatalf("expected one transport write, got %d", recorder.writeCount.Load())
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("coalesced first write payload mismatch")
	}
}

func TestPlanFirstBlockMatchesNinjaLayout(t *testing.T) {
	for _, existingPayloadLength := range []int{0, 20, firstBlockTarget + 1} {
		for _, overhead := range []int{0, 7, 255, firstBlockTarget - 1, firstBlockTarget, firstBlockTarget + 1} {
			for range 100 {
				paddingLength, payloadLength, err := planFirstBlock(overhead, existingPayloadLength)
				if err != nil {
					t.Fatal(err)
				}
				if overhead+existingPayloadLength >= firstBlockTarget {
					if paddingLength != 1 || payloadLength != existingPayloadLength {
						t.Fatalf("unexpected oversized plan: overhead=%d existing=%d padding=%d payload=%d", overhead, existingPayloadLength, paddingLength, payloadLength)
					}
					continue
				}
				if paddingLength < 1 || payloadLength < existingPayloadLength || overhead+paddingLength+payloadLength != firstBlockTarget+1 {
					t.Fatalf("unexpected plan: overhead=%d existing=%d padding=%d payload=%d", overhead, existingPayloadLength, paddingLength, payloadLength)
				}
			}
		}
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
