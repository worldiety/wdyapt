package openpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// SignDetached writes to w one detached signature (type 0x00, binary over
// data) per signing key, together in one ASCII armor, with SHA-512
// (Release.gpg).
func SignDetached(w io.Writer, data []byte, signers []*Entity, t time.Time) error {
	sigs, err := signAll(signers, sigBinary, t, data)
	if err != nil {
		return err
	}
	_, err = w.Write(Armor(SignatureBlock, sigs))
	return err
}

// SignCleartext writes text to w as cleartext signature (type 0x01 over the
// canonical form) with all signing keys and SHA-512 (InRelease). Lines that
// start with "-" are escaped as "- -". The signed text excludes the last
// line break before the signature block.
func SignCleartext(w io.Writer, text []byte, signers []*Entity, t time.Time) error {
	if bytes.Contains(text, []byte("\r")) {
		return errors.New("the text to sign contains a carriage return")
	}
	if len(text) > 0 && text[len(text)-1] != '\n' {
		text = append(bytes.Clone(text), '\n')
	}
	sigs, err := signAll(signers, sigText, t, canonical(text[:len(text)-1]))
	if err != nil {
		return err
	}
	var b bytes.Buffer
	b.WriteString("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n")
	for line := range strings.SplitSeq(string(text[:len(text)-1]), "\n") {
		if strings.HasPrefix(line, "-") {
			b.WriteString("- ")
		}
		b.WriteString(line + "\n")
	}
	b.Write(Armor(SignatureBlock, sigs))
	_, err = w.Write(b.Bytes())
	return err
}

func signAll(signers []*Entity, typ byte, t time.Time, data []byte) ([]byte, error) {
	if len(signers) == 0 {
		return nil, errors.New("no signing key")
	}
	var out []byte
	for _, e := range signers {
		key, err := e.SigningKey(t)
		if err != nil {
			return nil, err
		}
		s, err := sign(key.Private, typ, t, nil, data)
		if err != nil {
			return nil, err
		}
		out = append(out, s.packet()...)
	}
	return out, nil
}

// canonical builds the canonical text form: line endings CRLF, trailing
// spaces and tabs removed.
func canonical(text []byte) []byte {
	lines := strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return []byte(strings.Join(lines, "\r\n"))
}

// SignatureInfo describes a verified signature.
type SignatureInfo struct {
	// Signer is the primary key, Key the key that signed.
	Signer  Fingerprint
	Key     Fingerprint
	Created time.Time
	Hash    string
}

// VerifyDetached verifies detached signatures over data. It requires at
// least one valid signature by a key from k and no invalid one; signatures
// by unknown keys do not count.
func (k *Keyring) VerifyDetached(data, sig []byte) ([]SignatureInfo, error) {
	return k.verify(sig, func(s *Signature) ([][]byte, error) {
		if s.Type != sigBinary && s.Type != sigText {
			return nil, fmt.Errorf("signature of type %#x is no data signature", s.Type)
		}
		if s.Type == sigText {
			return [][]byte{canonical(data)}, nil
		}
		return [][]byte{data}, nil
	})
}

// VerifyCleartext verifies a cleartext signature and returns the text as it
// was signed, with the trailing line break that apt reads as well.
func (k *Keyring) VerifyCleartext(msg []byte) ([]byte, []SignatureInfo, error) {
	text, sig, err := splitCleartext(msg)
	if err != nil {
		return nil, nil, err
	}
	infos, err := k.verify(sig, func(s *Signature) ([][]byte, error) {
		if s.Type != sigText && s.Type != sigBinary {
			return nil, fmt.Errorf("signature of type %#x is no text signature", s.Type)
		}
		signed := text[:len(text)-1]
		if s.Type == sigText {
			return [][]byte{canonical(signed)}, nil
		}
		return [][]byte{signed}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return text, infos, nil
}

// ParseCleartext returns the text of a cleartext signature without
// verifying it.
func ParseCleartext(msg []byte) ([]byte, error) {
	text, _, err := splitCleartext(msg)
	return text, err
}

// splitCleartext splits a cleartext signature into the text (with a
// trailing "\n", dashes unescaped) and the signature packets.
func splitCleartext(msg []byte) ([]byte, []byte, error) {
	lines := strings.Split(strings.ReplaceAll(string(msg), "\r\n", "\n"), "\n")
	i := 0
	for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
		i++
	}
	if i >= len(lines) || strings.TrimRight(lines[i], " \t") != "-----BEGIN "+signedMessage+"-----" {
		return nil, nil, errors.New("not an OpenPGP cleartext signature")
	}
	i++
	for ; i < len(lines) && lines[i] != ""; i++ {
		key, value, ok := strings.Cut(lines[i], ": ")
		if !ok || key != "Hash" && key != "Charset" && key != "Comment" && key != "Version" {
			return nil, nil, fmt.Errorf("unexpected cleartext header %q", lines[i])
		}
		_ = value
	}
	if i >= len(lines) {
		return nil, nil, errors.New("cleartext signature without text")
	}
	i++
	var text []string
	for ; i < len(lines); i++ {
		if strings.TrimRight(lines[i], " \t") == "-----BEGIN "+SignatureBlock+"-----" {
			break
		}
		line := lines[i]
		if strings.HasPrefix(line, "- ") {
			line = line[2:]
		} else if strings.HasPrefix(line, "-") {
			return nil, nil, fmt.Errorf("unescaped dash line %q in cleartext signature", line)
		}
		text = append(text, line)
	}
	if i >= len(lines) {
		return nil, nil, errors.New("cleartext signature without signature block")
	}
	typ, body, rest, err := Dearmor([]byte(strings.Join(lines[i:], "\n")))
	if err != nil {
		return nil, nil, err
	}
	if typ != SignatureBlock {
		return nil, nil, fmt.Errorf("unexpected armor %q in cleartext signature", typ)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("data after the cleartext signature")
	}
	return []byte(strings.Join(text, "\n") + "\n"), body, nil
}

// verify verifies all signature packets in sig; parts returns what is
// hashed per signature.
func (k *Keyring) verify(sig []byte, parts func(*Signature) ([][]byte, error)) ([]SignatureInfo, error) {
	raw, err := unarmorAll(sig)
	if err != nil {
		return nil, err
	}
	packets, err := readPackets(raw)
	if err != nil {
		return nil, err
	}
	var infos []SignatureInfo
	unknown := 0
	now := time.Now()
	for _, p := range packets {
		if p.tag != tagSignature {
			return nil, fmt.Errorf("unexpected OpenPGP packet %d among signatures", p.tag)
		}
		s, err := parseSignature(p.body)
		if errors.Is(err, errUnsupportedSig) {
			unknown++
			continue
		}
		if err != nil {
			return nil, err
		}
		entity, key := k.lookup(s)
		if key == nil {
			unknown++
			continue
		}
		data, err := parts(s)
		if err != nil {
			return nil, err
		}
		if err := s.verify(key.Public, data...); err != nil {
			return nil, fmt.Errorf("invalid signature by %s: %w", entity.Fingerprint(), err)
		}
		if s.Created.After(now.Add(maxFutureCreation)) {
			return nil, fmt.Errorf("signature by %s was made in the future (%s)", entity.Fingerprint(), s.Created.Format(time.RFC3339))
		}
		if s.expiredAt(now) {
			return nil, fmt.Errorf("signature by %s expired", entity.Fingerprint())
		}
		if !key.canSignData() {
			return nil, fmt.Errorf("signature by %s was made with key %s, which may not sign", entity.Fingerprint(), key.Public.Fingerprint)
		}
		if err := key.validAt(s.Created); err != nil {
			return nil, fmt.Errorf("signature by %s: %w", entity.Fingerprint(), err)
		}
		infos = append(infos, SignatureInfo{Signer: entity.Fingerprint(), Key: key.Public.Fingerprint, Created: s.Created, Hash: hashName(s.HashAlgo)})
	}
	if len(infos) == 0 {
		if unknown > 0 {
			return nil, fmt.Errorf("signed only by keys that are not trusted (%d signatures); add the key with --trusted-key or --signing-key", unknown)
		}
		return nil, errors.New("no signature found")
	}
	return infos, nil
}

func hashName(id byte) string {
	switch id {
	case hashSHA1:
		return "SHA1"
	case hashSHA224:
		return "SHA224"
	case hashSHA256:
		return "SHA256"
	case hashSHA384:
		return "SHA384"
	case hashSHA512:
		return "SHA512"
	}
	return fmt.Sprintf("hash %d", id)
}
