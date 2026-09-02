package ninjav2

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
)

const base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
const base69 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%^&*"

type Encoded struct {
	Server       string
	Port         int
	Password     string
	NodePassword string
}

type Decoded struct {
	Server       string
	Port         int
	NodePassword string
}

func Decode(encoded Encoded) (Decoded, error) {
	label, suffix, _ := strings.Cut(encoded.Server, ".")
	dashIndex := strings.IndexByte(label, '-')
	if dashIndex < 3 || dashIndex == len(label)-1 {
		return Decoded{}, fmt.Errorf("invalid Ninja server label")
	}
	identifier := label[dashIndex-3 : dashIndex]
	payloadHead := label[dashIndex+1:]
	password := encoded.Password
	payload, overflowCount, overflow, decodedPassword, err := decodeNodePassword(encoded.NodePassword, payloadHead, password)
	if err != nil {
		return Decoded{}, err
	}
	restoredServer, err := decodeServer(identifier, payload+overflow, suffix, password, encoded.Port)
	if err != nil {
		return Decoded{}, err
	}
	return Decoded{Server: restoredServer, Port: decodePort(encoded.Port, password, overflowCount), NodePassword: decodedPassword}, nil
}

func decodeNodePassword(value, payloadHead, password string) (string, int, string, string, error) {
	decoded, err := decodeBase(value, shuffledAlphabet(base69, password))
	if err != nil {
		return "", 0, "", "", err
	}
	packed, err := inflateRaw(xorKey(decoded, []byte(payloadHead)))
	if err != nil {
		return payloadHead, 0, "", value, nil
	}
	separator := bytes.IndexByte(packed, 0x1f)
	if separator < 0 {
		return payloadHead, 0, "", value, nil
	}
	decodedPassword := string(packed[:separator])
	remainder := packed[separator+1:]
	hash := bytes.IndexByte(remainder, '#')
	if hash < 0 {
		return value, 0, "", decodedPassword, nil
	}
	var overflow int
	if _, err = fmt.Sscan(string(remainder[:hash]), &overflow); err != nil {
		return "", 0, "", "", err
	}
	return payloadHead, overflow, string(remainder[hash+1:]), decodedPassword, nil
}

func decodeServer(identifier, payload, suffix, password string, obfuscatedPort int) (string, error) {
	decoded, err := decodeBase(payload, shuffledAlphabet(base36, password))
	if err != nil {
		return "", err
	}
	key := []byte(fmt.Sprintf("%s:%d", password, obfuscatedPort))
	switch identifier {
	case "02a":
		if len(decoded) != 4 {
			return "", fmt.Errorf("invalid Ninja IPv4 payload")
		}
		value := uint32(decoded[0])<<24 | uint32(decoded[1])<<16 | uint32(decoded[2])<<8 | uint32(decoded[3])
		value ^= crc32.ChecksumIEEE([]byte(password)) ^ uint32(obfuscatedPort)
		return fmt.Sprintf("%d.%d.%d.%d", byte(value>>24), byte(value>>16), byte(value>>8), byte(value)), nil
	case "02b", "02c":
		return strings.ToLower(string(xorKey(decoded, key))), nil
	case "01a", "01b":
		prefix := string(xorKey(decoded, key))
		if suffix == "" {
			return prefix, nil
		}
		return prefix + "." + suffix, nil
	case "01c":
		value := xorKey(decoded, key)
		if inflated, err := inflateRaw(value); err == nil {
			return string(inflated), nil
		}
		return string(value), nil
	default:
		return "", fmt.Errorf("unknown Ninja server identifier %q", identifier)
	}
}

func decodePort(obfuscatedPort int, password string, overflowCount int) int {
	const portStart = 10000
	const span = 10001
	value := (obfuscatedPort - portStart) + overflowCount*span - int(crc32.ChecksumIEEE([]byte(password)))
	if value < 0 {
		return 0
	}
	if value > 65535 {
		return value % 65536
	}
	return value
}

func shuffledAlphabet(alphabet, password string) string {
	type characterHash struct {
		character byte
		digest    [32]byte
	}
	hashes := make([]characterHash, 0, len(alphabet))
	for characterIndex := range alphabet {
		character := alphabet[characterIndex]
		digest := sha256.Sum256(append(append([]byte(password), '|'), character))
		hashes = append(hashes, characterHash{character: character, digest: digest})
	}
	for leftIndex := range hashes {
		for rightIndex := leftIndex + 1; rightIndex < len(hashes); rightIndex++ {
			if bytes.Compare(hashes[leftIndex].digest[:], hashes[rightIndex].digest[:]) > 0 {
				hashes[leftIndex], hashes[rightIndex] = hashes[rightIndex], hashes[leftIndex]
			}
		}
	}
	result := make([]byte, len(hashes))
	for index, entry := range hashes {
		result[index] = entry.character
	}
	return string(result)
}

func decodeBase(value, alphabet string) ([]byte, error) {
	digitIndex := make(map[byte]int, len(alphabet))
	for index := range alphabet {
		digitIndex[alphabet[index]] = index
	}
	result := []byte{}
	leadingZeros := 0
	for leadingZeros < len(value) && value[leadingZeros] == alphabet[0] {
		leadingZeros++
	}
	for index := range value {
		digit, ok := digitIndex[value[index]]
		if !ok {
			return nil, fmt.Errorf("invalid Ninja base digit %q", value[index])
		}
		carry := digit
		for resultIndex := len(result) - 1; resultIndex >= 0; resultIndex-- {
			current := int(result[resultIndex])*len(alphabet) + carry
			result[resultIndex] = byte(current)
			carry = current >> 8
		}
		for carry > 0 {
			result = append([]byte{byte(carry)}, result...)
			carry >>= 8
		}
	}
	return append(make([]byte, leadingZeros), result...), nil
}
func xorKey(value, key []byte) []byte {
	digest := sha256.Sum256(key)
	result := make([]byte, len(value))
	for index := range value {
		result[index] = value[index] ^ digest[index%len(digest)]
	}
	return result
}
func inflateRaw(value []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(value))
	defer reader.Close()
	return io.ReadAll(reader)
}
