package ninjav2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPassInfoDecode(t *testing.T) {
	plain := []byte(`{"set":{"network":"ws","pass":true,"pass-opts":{"method":"aes-128-gcm","padding_min":64,"padding_mode":"min_random","padding_random_max":256,"password":"transport-password"},"ws-opts":{"path":"/m3u8","headers":{"Host":"microsoft.com"}},"servername":"microsoft.com","skip-cert-verify":true,"tls":true},"replace":[{"match":{"server":"old.example"},"replace":{"server":"new.example"}}]}`)
	for version, key := range map[int]string{1: "ninja-pass-info", 2: "ninja-pass2-info", 3: "ninja-pass3-info"} {
		digest := sha256.Sum256([]byte(key))
		encoded := append([]byte(nil), plain...)
		for index := range encoded {
			encoded[index] ^= digest[index%len(digest)]
		}
		info, err := decodePassInfo(base64.StdEncoding.EncodeToString(encoded), version)
		require.NoError(t, err)
		require.Equal(t, "ws", info.Set.Network)
		require.Equal(t, "transport-password", info.Set.PassOptions.Password)
		require.Equal(t, "microsoft.com", info.Set.WebsocketOptions.Headers["Host"])
		require.Equal(t, "new.example", info.replaceServer("old.example"))
	}
}

func TestPassConnFrames(t *testing.T) {
	leftRaw, rightRaw := net.Pipe()
	defer leftRaw.Close()
	defer rightRaw.Close()
	left, err := NewPassConn(leftRaw, AES128GCM, "transport-password", "min", 0, 0)
	require.NoError(t, err)
	right, err := NewPassConn(rightRaw, AES128GCM, "transport-password", "min", 0, 0)
	require.NoError(t, err)

	payload := []byte("client hello")
	writeResult := make(chan error, 1)
	go func() {
		_, writeErr := left.Write(payload)
		writeResult <- writeErr
	}()
	masterKey := kdfPass([]byte("transport-password"), 16)
	verify, err := hkdfPass(masterKey, passHKDFInfo, []byte("transport-password"), 16)
	require.NoError(t, err)
	expected := append(append(append([]byte{}, verify...), 0x01), payload...)
	actual := make([]byte, len(expected))
	_, err = io.ReadFull(right, actual)
	require.NoError(t, err)
	require.NoError(t, <-writeResult)
	require.Equal(t, expected, actual)

	followUp := []byte("second frame")
	go func() {
		_, writeErr := left.Write(followUp)
		writeResult <- writeErr
	}()
	actual = make([]byte, len(followUp))
	_, err = io.ReadFull(right, actual)
	require.NoError(t, err)
	require.NoError(t, <-writeResult)
	require.True(t, bytes.Equal(followUp, actual))
}

func TestPassConnSplitsLargeWrite(t *testing.T) {
	leftRaw, rightRaw := net.Pipe()
	defer leftRaw.Close()
	defer rightRaw.Close()
	left, err := NewPassConn(leftRaw, AES128GCM, "transport-password", "min", 0, 0)
	require.NoError(t, err)
	right, err := NewPassConn(rightRaw, AES128GCM, "transport-password", "min", 0, 0)
	require.NoError(t, err)

	payload := bytes.Repeat([]byte("x"), passMaxFrame+1024)
	type writeResult struct {
		count int
		err   error
	}
	result := make(chan writeResult, 1)
	go func() {
		count, writeErr := left.Write(payload)
		result <- writeResult{count: count, err: writeErr}
	}()

	masterKey := kdfPass([]byte("transport-password"), 16)
	verify, err := hkdfPass(masterKey, passHKDFInfo, []byte("transport-password"), 16)
	require.NoError(t, err)
	expected := append(append(append([]byte(nil), verify...), 1), payload...)
	actual := make([]byte, 0, len(expected))
	buffer := make([]byte, 4096)
	for len(actual) < len(expected) {
		chunk := make([]byte, len(buffer))
		count, readErr := right.Read(chunk)
		require.NoError(t, readErr)
		actual = append(actual, chunk[:count]...)
	}
	writeOutcome := <-result
	require.NoError(t, writeOutcome.err)
	require.Equal(t, len(payload), writeOutcome.count)
	require.Equal(t, expected, actual)
}

func TestPassVerificationVector(t *testing.T) {
	password := []byte("12f27790-82c8-4cbf-a804-b7c25a61a92d")
	verify, err := hkdfPass(kdfPass(password, 16), passHKDFInfo, password, 16)
	require.NoError(t, err)
	require.Equal(t, "16a935dd3daee433faac2fc17689c6b5", fmt.Sprintf("%x", verify))
}
