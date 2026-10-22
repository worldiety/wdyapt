// Package ssh speaks SSH-2 (RFC 4250 to 4254) in-process: version
// exchange, binary packets with AES-GCM or AES-CTR and HMAC, key exchange
// with ML-KEM hybrid, Curve25519, ECDH and Diffie-Hellman with SHA-2,
// host key verification, strict kex against Terrapin and key re-exchange
// (R-DEC-SSH-AND-SFTP-IN-PROCESS). SHA-1, CBC and ssh-rsa with SHA-1 are
// not used.
//
// Client and server share the same building blocks; only the test server
// in sshtest needs the server.
package ssh

import (
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
)

// Message numbers (RFC 4250, 4.1; appendix E of the implementation plan).
const (
	msgDisconnect     = 1
	msgIgnore         = 2
	msgUnimplemented  = 3
	msgDebug          = 4
	msgServiceRequest = 5
	msgServiceAccept  = 6
	msgExtInfo        = 7
	msgKexInit        = 20
	msgNewKeys        = 21
	msgKex30          = 30
	msgKex31          = 31

	msgUserauthRequest = 50
	msgUserauthFailure = 51
	msgUserauthSuccess = 52
	msgUserauthBanner  = 53
	msgUserauth60      = 60
	msgUserauth61      = 61

	msgGlobalRequest  = 80
	msgRequestSuccess = 81
	msgRequestFailure = 82

	msgChannelOpen         = 90
	msgChannelOpenConfirm  = 91
	msgChannelOpenFailure  = 92
	msgChannelWindowAdjust = 93
	msgChannelData         = 94
	msgChannelExtendedData = 95
	msgChannelEOF          = 96
	msgChannelClose        = 97
	msgChannelRequest      = 98
	msgChannelSuccess      = 99
	msgChannelFailure      = 100
)

// Reasons for DISCONNECT (RFC 4250, 4.2.2).
const (
	disconnectProtocolError    = 2
	disconnectKeyExchange      = 3
	disconnectMACError         = 5
	disconnectHostKeyNotVerify = 9
	disconnectByApplication    = 11
)

var errShort = errors.New("ssh: malformed message")

// builder writes the types of RFC 4251, section 5.
type builder struct{ b []byte }

func newBuilder(msg byte) *builder { return &builder{b: []byte{msg}} }

func (w *builder) byte(v byte) *builder { w.b = append(w.b, v); return w }

func (w *builder) bool(v bool) *builder {
	if v {
		return w.byte(1)
	}
	return w.byte(0)
}

func (w *builder) uint32(v uint32) *builder { w.b = binary.BigEndian.AppendUint32(w.b, v); return w }

func (w *builder) string(v []byte) *builder {
	w.uint32(uint32(len(v)))
	w.b = append(w.b, v...)
	return w
}

func (w *builder) text(v string) *builder { return w.string([]byte(v)) }

func (w *builder) nameList(v []string) *builder { return w.text(strings.Join(v, ",")) }

func (w *builder) raw(v []byte) *builder { w.b = append(w.b, v...); return w }

// mpint writes a non-negative number as an mpint.
func (w *builder) mpint(v *big.Int) *builder { return w.raw(encodeMpint(v.Bytes())) }

// encodeMpint builds an mpint from the bytes of a non-negative number:
// without leading zeros, with a zero in front if the highest bit is
// set.
func encodeMpint(v []byte) []byte {
	for len(v) > 0 && v[0] == 0 {
		v = v[1:]
	}
	if len(v) > 0 && v[0]&0x80 != 0 {
		v = append([]byte{0}, v...)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(len(v)))
	return append(out, v...)
}

// encodeString builds an SSH string.
func encodeString(v []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(v)))
	return append(out, v...)
}

// parser reads the types of RFC 4251.
type parser struct {
	b   []byte
	err error
}

func newParser(b []byte) *parser { return &parser{b: b} }

func (p *parser) fail() {
	if p.err == nil {
		p.err = errShort
	}
}

func (p *parser) bytes(n int) []byte {
	if p.err != nil || n < 0 || n > len(p.b) {
		p.fail()
		return nil
	}
	v := p.b[:n:n]
	p.b = p.b[n:]
	return v
}

func (p *parser) byte() byte {
	v := p.bytes(1)
	if v == nil {
		return 0
	}
	return v[0]
}

func (p *parser) bool() bool { return p.byte() != 0 }

func (p *parser) uint32() uint32 {
	v := p.bytes(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (p *parser) string() []byte { return p.bytes(int(p.uint32())) }

func (p *parser) text() string { return string(p.string()) }

func (p *parser) nameList() []string {
	s := p.text()
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// mpint reads a non-negative number.
func (p *parser) mpint() *big.Int {
	v := p.string()
	if p.err != nil {
		return nil
	}
	if len(v) > 0 && v[0]&0x80 != 0 {
		p.err = errors.New("ssh: negative mpint")
		return nil
	}
	return new(big.Int).SetBytes(v)
}

func (p *parser) rest() []byte {
	v := p.b
	p.b = nil
	return v
}

// done reports an error if bytes are left over.
func (p *parser) done() error {
	if p.err == nil && len(p.b) != 0 {
		return errors.New("ssh: trailing data in message")
	}
	return p.err
}
