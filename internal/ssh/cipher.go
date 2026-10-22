package ssh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// maxPacket limits incoming packets; the server is hostile until proven
// otherwise.
const maxPacket = 256 << 10

// Ciphers and MACs in the order the client prefers.
var (
	defaultCiphers = []string{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"}
	defaultMACs    = []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"}
)

// cipherSpec describes a cipher: key and IV length, and whether it needs
// a separate MAC.
type cipherSpec struct {
	keyLen, ivLen int
	aead          bool
}

var cipherSpecs = map[string]cipherSpec{
	"aes128-gcm@openssh.com": {16, 12, true},
	"aes256-gcm@openssh.com": {32, 12, true},
	"aes128-ctr":             {16, 16, false},
	"aes192-ctr":             {24, 16, false},
	"aes256-ctr":             {32, 16, false},
}

type macSpec struct {
	keyLen int
	etm    bool
	new    func() hash.Hash
}

var macSpecs = map[string]macSpec{
	"hmac-sha2-256":                 {32, false, sha256.New},
	"hmac-sha2-512":                 {64, false, sha512.New},
	"hmac-sha2-256-etm@openssh.com": {32, true, sha256.New},
	"hmac-sha2-512-etm@openssh.com": {64, true, sha512.New},
}

// packetCipher writes and reads binary packets of one direction.
type packetCipher interface {
	writePacket(seq uint32, w io.Writer, payload []byte) error
	readPacket(seq uint32, r io.Reader) ([]byte, error)
}

// padding builds the padding: at least 4 random bytes, such that the
// length of unaligned plus padding is a multiple of block.
func padding(unaligned, block int) []byte {
	n := block - unaligned%block
	if n < 4 {
		n += block
	}
	p := make([]byte, n)
	rand.Read(p)
	return p
}

// noneCipher applies until the first NEWKEYS.
type noneCipher struct{}

func (noneCipher) writePacket(_ uint32, w io.Writer, payload []byte) error {
	pad := padding(5+len(payload), 8)
	buf := make([]byte, 0, 5+len(payload)+len(pad))
	buf = binary.BigEndian.AppendUint32(buf, uint32(1+len(payload)+len(pad)))
	buf = append(buf, byte(len(pad)))
	buf = append(buf, payload...)
	buf = append(buf, pad...)
	_, err := w.Write(buf)
	return err
}

func (noneCipher) readPacket(_ uint32, r io.Reader) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(head[:4])
	if length < 5 || length > maxPacket {
		return nil, fmt.Errorf("ssh: invalid packet length %d", length)
	}
	rest := make([]byte, length-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	pad := int(head[4])
	if pad < 4 || pad > len(rest) {
		return nil, errors.New("ssh: invalid padding")
	}
	return rest[:len(rest)-pad], nil
}

// gcmCipher is aes*-gcm@openssh.com: the length unencrypted as AAD, the
// rest encrypted with a 16-byte tag; the last 8 bytes of the nonce count
// up per packet.
type gcmCipher struct {
	aead  cipher.AEAD
	nonce [12]byte
}

func newGCM(key, iv []byte) (*gcmCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &gcmCipher{aead: aead}
	copy(c.nonce[:], iv)
	return c, nil
}

func (c *gcmCipher) inc() {
	n := binary.BigEndian.Uint64(c.nonce[4:])
	binary.BigEndian.PutUint64(c.nonce[4:], n+1)
}

func (c *gcmCipher) writePacket(_ uint32, w io.Writer, payload []byte) error {
	pad := padding(1+len(payload), 16)
	length := 1 + len(payload) + len(pad)
	buf := make([]byte, 4, 4+length+c.aead.Overhead())
	binary.BigEndian.PutUint32(buf, uint32(length))
	plain := make([]byte, 0, length)
	plain = append(plain, byte(len(pad)))
	plain = append(plain, payload...)
	plain = append(plain, pad...)
	buf = c.aead.Seal(buf, c.nonce[:], plain, buf[:4])
	c.inc()
	_, err := w.Write(buf)
	return err
}

func (c *gcmCipher) readPacket(_ uint32, r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(head[:])
	if length < 16 || length > maxPacket || length%16 != 0 {
		return nil, fmt.Errorf("ssh: invalid packet length %d", length)
	}
	sealed := make([]byte, int(length)+c.aead.Overhead())
	if _, err := io.ReadFull(r, sealed); err != nil {
		return nil, err
	}
	plain, err := c.aead.Open(sealed[:0], c.nonce[:], sealed, head[:])
	if err != nil {
		return nil, errMAC
	}
	c.inc()
	pad := int(plain[0])
	if pad < 4 || pad >= len(plain) {
		return nil, errors.New("ssh: invalid padding")
	}
	return plain[1 : len(plain)-pad], nil
}

var errMAC = errors.New("ssh: message authentication failed")

// ctrCipher is aes*-ctr with HMAC, classic (MAC over the plaintext) or
// encrypt-then-MAC (length unencrypted, MAC over the ciphertext, checked
// before decrypting).
type ctrCipher struct {
	stream cipher.Stream
	mac    hash.Hash
	etm    bool
}

func newCTR(key, iv, macKey []byte, m macSpec) (*ctrCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ctrCipher{stream: cipher.NewCTR(block, iv), mac: hmac.New(m.new, macKey), etm: m.etm}, nil
}

func (c *ctrCipher) sum(seq uint32, parts ...[]byte) []byte {
	c.mac.Reset()
	var s [4]byte
	binary.BigEndian.PutUint32(s[:], seq)
	c.mac.Write(s[:])
	for _, p := range parts {
		c.mac.Write(p)
	}
	return c.mac.Sum(nil)
}

func (c *ctrCipher) writePacket(seq uint32, w io.Writer, payload []byte) error {
	var pad []byte
	if c.etm {
		pad = padding(1+len(payload), 16)
	} else {
		pad = padding(5+len(payload), 16)
	}
	length := 1 + len(payload) + len(pad)
	buf := make([]byte, 0, 4+length+c.mac.Size())
	buf = binary.BigEndian.AppendUint32(buf, uint32(length))
	buf = append(buf, byte(len(pad)))
	buf = append(buf, payload...)
	buf = append(buf, pad...)
	if c.etm {
		c.stream.XORKeyStream(buf[4:], buf[4:])
		buf = append(buf, c.sum(seq, buf)...)
	} else {
		mac := c.sum(seq, buf)
		c.stream.XORKeyStream(buf, buf)
		buf = append(buf, mac...)
	}
	_, err := w.Write(buf)
	return err
}

func (c *ctrCipher) readPacket(seq uint32, r io.Reader) ([]byte, error) {
	if c.etm {
		var head [4]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(head[:])
		if length < 16 || length > maxPacket || length%16 != 0 {
			return nil, fmt.Errorf("ssh: invalid packet length %d", length)
		}
		body := make([]byte, int(length)+c.mac.Size())
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		enc, mac := body[:length], body[length:]
		if !hmac.Equal(mac, c.sum(seq, head[:], enc)) {
			return nil, errMAC
		}
		c.stream.XORKeyStream(enc, enc)
		return unpad(enc)
	}
	first := make([]byte, 16)
	if _, err := io.ReadFull(r, first); err != nil {
		return nil, err
	}
	c.stream.XORKeyStream(first, first)
	length := binary.BigEndian.Uint32(first[:4])
	if length < 12 || length > maxPacket || (length+4)%16 != 0 {
		return nil, fmt.Errorf("ssh: invalid packet length %d", length)
	}
	rest := make([]byte, int(length)+4-16+c.mac.Size())
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	enc, mac := rest[:len(rest)-c.mac.Size()], rest[len(rest)-c.mac.Size():]
	c.stream.XORKeyStream(enc, enc)
	packet := append(first, enc...)
	if !hmac.Equal(mac, c.sum(seq, packet)) {
		return nil, errMAC
	}
	return unpad(packet[4:])
}

func unpad(b []byte) ([]byte, error) {
	pad := int(b[0])
	if pad < 4 || pad >= len(b) {
		return nil, errors.New("ssh: invalid padding")
	}
	return b[1 : len(b)-pad], nil
}

// newPacketCipher builds the cipher of one direction from the derived
// keys.
func newPacketCipher(cipherName, macName string, key, iv, macKey []byte) (packetCipher, error) {
	spec := cipherSpecs[cipherName]
	if spec.aead {
		return newGCM(key, iv)
	}
	m, ok := macSpecs[macName]
	if !ok {
		return nil, fmt.Errorf("ssh: unsupported MAC %q", macName)
	}
	return newCTR(key, iv, macKey, m)
}
