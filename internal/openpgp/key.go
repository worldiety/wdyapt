package openpgp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Public key algorithms (RFC 9580, 9.1).
const (
	algoRSA         = 1
	algoRSAEncrypt  = 2
	algoRSASign     = 3
	algoElgamal     = 16
	algoDSA         = 17
	algoECDH        = 18
	algoECDSA       = 19
	algoEdDSALegacy = 22
	algoX25519      = 25
	algoX448        = 26
	algoEd25519     = 27
	algoEd448       = 28
)

// oidEd25519 is the curve of EdDSALegacy (1.3.6.1.4.1.11591.15.1).
var oidEd25519 = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}

// Curves that wdyapt calls by name.
var curveNames = map[string]string{
	hex.EncodeToString(oidEd25519): "Ed25519",
	"2b060104019755010501":         "Curve25519",
	"2a8648ce3d030107":             "NIST P-256",
	"2b81040022":                   "NIST P-384",
	"2b81040023":                   "NIST P-521",
	"2b2403030208010107":           "brainpoolP256r1",
	"2b240303020801010b":           "brainpoolP384r1",
	"2b240303020801010d":           "brainpoolP512r1",
	"2b8104000a":                   "secp256k1",
}

// Fingerprint is the v4 fingerprint of a key.
type Fingerprint [20]byte

// String writes the fingerprint in upper case, like gpg.
func (f Fingerprint) String() string { return strings.ToUpper(hex.EncodeToString(f[:])) }

// KeyID is the part of the fingerprint that gpg shows as long key ID.
func (f Fingerprint) KeyID() uint64 { return binary.BigEndian.Uint64(f[12:]) }

// PublicKey is the public part of a version 4 key.
type PublicKey struct {
	Created     time.Time
	Algo        byte
	Fingerprint Fingerprint
	// body is the packet content up to the end of the public part; it goes
	// into the fingerprint and binding signatures.
	body []byte

	rsa     *rsa.PublicKey
	ed25519 ed25519.PublicKey
	bits    int
	curve   string
}

// KeyID is the long key ID of the key.
func (k *PublicKey) KeyID() uint64 { return k.Fingerprint.KeyID() }

// CanSign reports whether wdyapt can sign and verify with this algorithm.
func (k *PublicKey) CanSign() bool { return k.rsa != nil || k.ed25519 != nil }

// AlgoName describes algorithm and size, such as "ed25519" or "rsa3072".
func (k *PublicKey) AlgoName() string {
	switch k.Algo {
	case algoRSA, algoRSAEncrypt, algoRSASign:
		return fmt.Sprintf("rsa%d", k.bits)
	case algoEdDSALegacy:
		return "ed25519 (EdDSA legacy)"
	case algoEd25519:
		return "ed25519"
	case algoEd448:
		return "ed448"
	case algoX25519:
		return "x25519"
	case algoX448:
		return "x448"
	case algoDSA:
		return fmt.Sprintf("dsa%d", k.bits)
	case algoElgamal:
		return fmt.Sprintf("elgamal%d", k.bits)
	case algoECDH:
		return "ecdh " + k.curve
	case algoECDSA:
		return "ecdsa " + k.curve
	}
	return fmt.Sprintf("algorithm %d", k.Algo)
}

// hashPrefix is what is hashed for the key in binding signatures: 0x99, two
// bytes of length, the public part.
func (k *PublicKey) hashPrefix() []byte {
	out := []byte{0x99, byte(len(k.body) >> 8), byte(len(k.body))}
	return append(out, k.body...)
}

// parsePublicKey reads the public part at the start of body and returns the
// rest, which for secret keys is the secret part.
func parsePublicKey(body []byte) (*PublicKey, []byte, error) {
	r := &reader{b: body}
	version := r.byte()
	if r.err != nil {
		return nil, nil, r.err
	}
	if version != 4 {
		return nil, nil, fmt.Errorf("OpenPGP key version %d is not supported; only version 4 keys are, as GnuPG creates them by default", version)
	}
	k := &PublicKey{Created: time.Unix(int64(r.uint32()), 0).UTC(), Algo: r.byte()}
	switch k.Algo {
	case algoRSA, algoRSAEncrypt, algoRSASign:
		n, e := r.mpi(), r.mpi()
		if r.err == nil {
			ev := new(big.Int).SetBytes(e)
			if !ev.IsInt64() || ev.Int64() > 1<<31-1 || ev.Int64() < 3 {
				return nil, nil, fmt.Errorf("RSA key with unusable exponent")
			}
			k.rsa = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ev.Int64())}
			k.bits = k.rsa.N.BitLen()
		}
	case algoDSA:
		p := r.mpi()
		r.mpi()
		r.mpi()
		r.mpi()
		k.bits = len(p) * 8
	case algoElgamal:
		p := r.mpi()
		r.mpi()
		r.mpi()
		k.bits = len(p) * 8
	case algoECDSA, algoEdDSALegacy, algoECDH:
		oid := r.bytes(int(r.byte()))
		point := r.mpi()
		k.curve = curveNames[hex.EncodeToString(oid)]
		if k.curve == "" {
			k.curve = "unknown curve"
		}
		if k.Algo == algoECDH {
			r.bytes(int(r.byte())) // KDF parameters
		}
		if k.Algo == algoEdDSALegacy && r.err == nil {
			if !bytes.Equal(oid, oidEd25519) {
				return nil, nil, fmt.Errorf("EdDSA key on %s is not supported", k.curve)
			}
			if len(point) != 33 || point[0] != 0x40 {
				return nil, nil, fmt.Errorf("broken Ed25519 key")
			}
			k.ed25519 = ed25519.PublicKey(bytes.Clone(point[1:]))
		}
	case algoX25519:
		r.bytes(32)
	case algoX448:
		r.bytes(56)
	case algoEd25519:
		k.ed25519 = ed25519.PublicKey(bytes.Clone(r.bytes(32)))
	case algoEd448:
		r.bytes(57)
	default:
		return nil, nil, fmt.Errorf("unknown public key algorithm %d", k.Algo)
	}
	if r.err != nil {
		return nil, nil, fmt.Errorf("broken public key: %w", r.err)
	}
	k.body = bytes.Clone(body[:len(body)-len(r.b)])
	k.Fingerprint = sha1.Sum(k.hashPrefix())
	return k, r.b, nil
}

// encodePublicEd25519 builds the public part of an EdDSALegacy key.
func encodePublicEd25519(created time.Time, pub ed25519.PublicKey) []byte {
	b := []byte{4}
	b = binary.BigEndian.AppendUint32(b, uint32(created.Unix()))
	b = append(b, algoEdDSALegacy, byte(len(oidEd25519)))
	b = append(b, oidEd25519...)
	return append(b, mpi(append([]byte{0x40}, pub...))...)
}
