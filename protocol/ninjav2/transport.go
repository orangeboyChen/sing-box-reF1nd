package ninjav2

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type Destination struct {
	Host string
	Port uint16
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
		for len(chunk) > 0 {
			written, err := writer.Write(chunk)
			if err != nil {
				return err
			}
			if written == 0 {
				return io.ErrShortWrite
			}
			chunk = chunk[written:]
		}
	}
	return nil
}
func appendTransportPort(data []byte, port uint16) []byte {
	return binary.BigEndian.AppendUint16(data, port)
}
func encodeTransportDestination(destination Destination) ([]byte, error) {
	if destination.Host == "" || destination.Port == 0 {
		return nil, fmt.Errorf("NinjaV2 destination host and port are required")
	}
	if address := net.ParseIP(destination.Host); address != nil {
		if ipv4 := address.To4(); ipv4 != nil {
			return appendTransportPort(append([]byte{1}, ipv4...), destination.Port), nil
		}
		return appendTransportPort(append([]byte{4}, address.To16()...), destination.Port), nil
	}
	if len(destination.Host) > 255 {
		return nil, fmt.Errorf("NinjaV2 hostname is too long")
	}
	return appendTransportPort(append([]byte{3, byte(len(destination.Host))}, destination.Host...), destination.Port), nil
}
