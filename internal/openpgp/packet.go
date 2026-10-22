package openpgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Packet types (RFC 9580, 5).
const (
	tagSignature     = 2
	tagSecretKey     = 5
	tagPublicKey     = 6
	tagSecretSubkey  = 7
	tagMarker        = 10
	tagTrust         = 12
	tagUserID        = 13
	tagPublicSubkey  = 14
	tagUserAttribute = 17
)

// packet is a parsed packet: type and content.
type packet struct {
	tag  byte
	body []byte
}

// maxPacket limits the size of a packet; keys and signatures are small.
const maxPacket = 1 << 20

// readPackets splits data into packets in the new and the old format.
// Partial lengths do not occur in keys and signatures and are an error.
func readPackets(data []byte) ([]packet, error) {
	var out []packet
	for len(data) > 0 {
		b := data[0]
		if b&0x80 == 0 {
			return nil, fmt.Errorf("broken OpenPGP data: byte %#x is no packet header", b)
		}
		var tag byte
		var length, hlen int
		if b&0x40 != 0 {
			tag = b & 0x3F
			if len(data) < 2 {
				return nil, errTruncated
			}
			switch l := data[1]; {
			case l < 192:
				length, hlen = int(l), 2
			case l < 224:
				if len(data) < 3 {
					return nil, errTruncated
				}
				length, hlen = (int(l)-192)<<8+int(data[2])+192, 3
			case l == 255:
				if len(data) < 6 {
					return nil, errTruncated
				}
				length, hlen = int(binary.BigEndian.Uint32(data[2:6])), 6
			default:
				return nil, fmt.Errorf("OpenPGP packets with partial lengths are not supported here")
			}
		} else {
			tag = (b >> 2) & 0x0F
			switch b & 3 {
			case 0:
				if len(data) < 2 {
					return nil, errTruncated
				}
				length, hlen = int(data[1]), 2
			case 1:
				if len(data) < 3 {
					return nil, errTruncated
				}
				length, hlen = int(binary.BigEndian.Uint16(data[1:3])), 3
			case 2:
				if len(data) < 5 {
					return nil, errTruncated
				}
				length, hlen = int(binary.BigEndian.Uint32(data[1:5])), 5
			case 3:
				length, hlen = len(data)-1, 1
			}
		}
		if length < 0 || length > maxPacket || hlen+length > len(data) {
			return nil, errTruncated
		}
		out = append(out, packet{tag: tag, body: data[hlen : hlen+length]})
		data = data[hlen+length:]
	}
	return out, nil
}

var errTruncated = errors.New("broken OpenPGP data: truncated packet")

// writePacket writes a packet in the new format.
func writePacket(tag byte, body []byte) []byte {
	out := []byte{0xC0 | tag}
	switch n := len(body); {
	case n < 192:
		out = append(out, byte(n))
	case n < 8384:
		n -= 192
		out = append(out, byte(n>>8)+192, byte(n))
	default:
		out = append(out, 255, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// reader reads fields from a packet content.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = errTruncated
	}
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.fail()
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) byte() byte {
	v := r.bytes(1)
	if v == nil {
		return 0
	}
	return v[0]
}

func (r *reader) uint16() uint16 {
	v := r.bytes(2)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint16(v)
}

func (r *reader) uint32() uint32 {
	v := r.bytes(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

// mpi reads a number preceded by its bit length (RFC 9580, 3.2).
func (r *reader) mpi() []byte {
	bits := int(r.uint16())
	return r.bytes((bits + 7) / 8)
}

// mpi writes v as a number with bit length; leading zero bytes are dropped.
func mpi(v []byte) []byte {
	for len(v) > 0 && v[0] == 0 {
		v = v[1:]
	}
	bits := 0
	if len(v) > 0 {
		bits = (len(v)-1)*8 + bitLen(v[0])
	}
	return append([]byte{byte(bits >> 8), byte(bits)}, v...)
}

func bitLen(b byte) int {
	n := 0
	for b != 0 {
		n++
		b >>= 1
	}
	return n
}

func mpiInt(v *big.Int) []byte { return mpi(v.Bytes()) }

// leftPad pads v at the front with zeros to n bytes. The result never
// shares memory with v.
func leftPad(v []byte, n int) []byte {
	if len(v) >= n {
		return bytes.Clone(v[len(v)-n:])
	}
	out := make([]byte, n)
	copy(out[n-len(v):], v)
	return out
}
