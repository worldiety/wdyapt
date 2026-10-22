// Package openpgp signs and verifies with OpenPGP (RFC 9580, version 4 keys
// and signatures only), without gpg or gpgv (R-DEC-OPENPGP-IN-PROCESS). It
// reads keys exported by GnuPG, generates its own Ed25519 keys, signs
// detached and as cleartext signature and verifies both against a keyring.
//
// Supported are RSA, EdDSALegacy (Ed25519, algorithm 22) and Ed25519
// (algorithm 27), hashes of the SHA-2 family, and secret keys that are
// unprotected or protected with iterated and salted S2K and AES. Other
// algorithms are read and skipped.
package openpgp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Armor types.
const (
	PublicKeyBlock  = "PGP PUBLIC KEY BLOCK"
	PrivateKeyBlock = "PGP PRIVATE KEY BLOCK"
	SignatureBlock  = "PGP SIGNATURE"
	signedMessage   = "PGP SIGNED MESSAGE"
)

// crc24 is the checksum of the ASCII armor (RFC 9580, 6.1).
func crc24(data []byte) uint32 {
	crc := uint32(0xB704CE)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864CFB
			}
		}
	}
	return crc & 0xFFFFFF
}

// Armor writes data in an ASCII armor of type typ: Base64 in lines of 64
// characters and the CRC-24 checksum.
func Armor(typ string, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "-----BEGIN %s-----\n\n", typ)
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	if enc != "" {
		b.WriteString(enc + "\n")
	}
	crc := crc24(data)
	fmt.Fprintf(&b, "=%s\n", base64.StdEncoding.EncodeToString([]byte{byte(crc >> 16), byte(crc >> 8), byte(crc)}))
	fmt.Fprintf(&b, "-----END %s-----\n", typ)
	return b.Bytes()
}

// errNoArmor reports data without ASCII armor.
var errNoArmor = errors.New("no ASCII armor")

// Dearmor reads the first ASCII armor from data and returns its type and
// content. Header lines are skipped, a checksum is verified if present.
func Dearmor(data []byte) (typ string, body []byte, rest []byte, err error) {
	start := bytes.Index(data, []byte("-----BEGIN "))
	if start < 0 {
		return "", nil, nil, errNoArmor
	}
	sc := bufio.NewScanner(bytes.NewReader(data[start:]))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	if !sc.Scan() {
		return "", nil, nil, errNoArmor
	}
	first := strings.TrimRight(sc.Text(), " \t\r")
	if !strings.HasSuffix(first, "-----") {
		return "", nil, nil, fmt.Errorf("broken armor line %q", first)
	}
	typ = strings.TrimSuffix(strings.TrimPrefix(first, "-----BEGIN "), "-----")
	consumed := len(sc.Bytes()) + 1
	// Header lines up to the first empty line. Some writers omit the empty
	// line; then the content starts right away.
	var lines []string
	inHeaders := true
	end := "-----END " + typ + "-----"
	done := false
	for sc.Scan() {
		consumed += len(sc.Bytes()) + 1
		line := strings.TrimRight(sc.Text(), " \t\r")
		if inHeaders {
			if line == "" {
				inHeaders = false
				continue
			}
			if strings.Contains(line, ": ") {
				continue
			}
			inHeaders = false
		}
		if line == end {
			done = true
			break
		}
		lines = append(lines, line)
	}
	if !done {
		return "", nil, nil, fmt.Errorf("armor of type %q has no end line", typ)
	}
	var checksum string
	if n := len(lines); n > 0 && strings.HasPrefix(lines[n-1], "=") && len(lines[n-1]) == 5 {
		checksum, lines = lines[n-1][1:], lines[:n-1]
	}
	body, err = base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		return "", nil, nil, fmt.Errorf("armor of type %q: %w", typ, err)
	}
	if checksum != "" {
		want, err := base64.StdEncoding.DecodeString(checksum)
		if err != nil || len(want) != 3 {
			return "", nil, nil, fmt.Errorf("armor of type %q: broken checksum", typ)
		}
		crc := crc24(body)
		if want[0] != byte(crc>>16) || want[1] != byte(crc>>8) || want[2] != byte(crc) {
			return "", nil, nil, fmt.Errorf("armor of type %q: checksum mismatch", typ)
		}
	}
	rest = data[min(start+consumed, len(data)):]
	return typ, body, rest, nil
}

// readAll reads all of r, at most limit bytes.
func readAll(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input larger than %d bytes", limit)
	}
	return data, nil
}

// unarmorAll returns the packets in data: from all ASCII armors, or data
// itself if it is binary.
func unarmorAll(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0]&0x80 != 0 {
		return data, nil
	}
	var all []byte
	rest := data
	for {
		_, body, r, err := Dearmor(rest)
		if errors.Is(err, errNoArmor) {
			break
		}
		if err != nil {
			return nil, err
		}
		all = append(all, body...)
		rest = r
	}
	if all == nil {
		return nil, fmt.Errorf("neither binary OpenPGP data nor ASCII armor")
	}
	return all, nil
}
