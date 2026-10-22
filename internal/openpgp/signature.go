package openpgp

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Signature types (RFC 9580, 5.2.1).
const (
	sigBinary           = 0x00
	sigText             = 0x01
	sigCertGeneric      = 0x10
	sigCertPositive     = 0x13
	sigSubkeyBinding    = 0x18
	sigPrimaryBinding   = 0x19
	sigDirectKey        = 0x1F
	sigKeyRevocation    = 0x20
	sigSubkeyRevocation = 0x28
)

// Subpackets (RFC 9580, 5.2.3.7).
const (
	subCreated        = 2
	subSigExpires     = 3
	subKeyExpires     = 9
	subPrefSymmetric  = 11
	subIssuerKeyID    = 16
	subPrefHash       = 21
	subPrimaryUserID  = 25
	subKeyFlags       = 27
	subFeatures       = 30
	subEmbedded       = 32
	subIssuerFP       = 33
	flagCertify       = 0x01
	flagSign          = 0x02
	flagEncryptComms  = 0x04
	flagEncryptStore  = 0x08
	flagAuthenticate  = 0x20
	critical          = 0x80
	maxFutureCreation = 5 * time.Minute
)

// Signature is a version 4 signature.
type Signature struct {
	Type     byte
	PubAlgo  byte
	HashAlgo byte
	Created  time.Time
	// SigExpires and KeyExpires are durations from the creation of the
	// signature or the key; 0 means never.
	SigExpires  time.Duration
	KeyExpires  time.Duration
	KeyFlags    byte
	HasKeyFlags bool
	PrimaryUID  bool
	IssuerFP    []byte
	IssuerKeyID uint64
	Embedded    *Signature

	// hashed is the hashed part: from the version to the end of the hashed
	// subpackets.
	hashed []byte
	left16 [2]byte
	rsaSig []byte
	edR    []byte
	edS    []byte
	raw    []byte // whole packet content
}

// errUnsupportedSig reports a signature that wdyapt cannot verify.
var errUnsupportedSig = errors.New("unsupported signature")

// parseSignature reads a signature. Signatures of other versions return
// errUnsupportedSig.
func parseSignature(body []byte) (*Signature, error) {
	r := &reader{b: body}
	version := r.byte()
	if r.err != nil {
		return nil, r.err
	}
	if version != 4 {
		return nil, fmt.Errorf("%w: version %d", errUnsupportedSig, version)
	}
	s := &Signature{Type: r.byte(), PubAlgo: r.byte(), HashAlgo: r.byte(), raw: bytes.Clone(body)}
	hashedLen := int(r.uint16())
	hashed := r.bytes(hashedLen)
	if r.err != nil {
		return nil, fmt.Errorf("broken signature: %w", r.err)
	}
	s.hashed = bytes.Clone(body[:6+hashedLen])
	created := false
	if err := s.parseSubpackets(hashed, true, &created); err != nil {
		return nil, err
	}
	unhashed := r.bytes(int(r.uint16()))
	if r.err != nil {
		return nil, fmt.Errorf("broken signature: %w", r.err)
	}
	if err := s.parseSubpackets(unhashed, false, &created); err != nil {
		return nil, err
	}
	if !created {
		return nil, fmt.Errorf("broken signature: no creation time")
	}
	copy(s.left16[:], r.bytes(2))
	switch s.PubAlgo {
	case algoRSA, algoRSASign:
		s.rsaSig = r.mpi()
	case algoEdDSALegacy:
		s.edR, s.edS = r.mpi(), r.mpi()
	case algoEd25519:
		sig := r.bytes(64)
		if len(sig) == 64 {
			s.edR, s.edS = sig[:32], sig[32:]
		}
	default:
		return s, nil
	}
	if r.err != nil {
		return nil, fmt.Errorf("broken signature: %w", r.err)
	}
	return s, nil
}

// parseSubpackets reads subpackets. Whatever counts must be hashed; only
// the issuer key ID may be unhashed.
func (s *Signature) parseSubpackets(data []byte, hashed bool, created *bool) error {
	for len(data) > 0 {
		var length int
		switch b := data[0]; {
		case b < 192:
			length, data = int(b), data[1:]
		case b < 255:
			if len(data) < 2 {
				return errTruncated
			}
			length, data = (int(b)-192)<<8+int(data[1])+192, data[2:]
		default:
			if len(data) < 5 {
				return errTruncated
			}
			length, data = int(binary.BigEndian.Uint32(data[1:5])), data[5:]
		}
		if length < 1 || length > len(data) {
			return errTruncated
		}
		typ, v := data[0], data[1:length]
		data = data[length:]
		crit := typ&critical != 0
		typ &^= critical
		if !hashed {
			switch typ {
			case subIssuerKeyID:
				if len(v) == 8 && s.IssuerKeyID == 0 {
					s.IssuerKeyID = binary.BigEndian.Uint64(v)
				}
			case subIssuerFP:
				if len(v) == 21 && v[0] == 4 && s.IssuerFP == nil {
					s.IssuerFP = bytes.Clone(v[1:])
				}
			case subEmbedded:
				if emb, err := parseSignature(v); err == nil {
					s.Embedded = emb
				}
			}
			continue
		}
		switch typ {
		case subCreated:
			if len(v) != 4 {
				return fmt.Errorf("broken signature creation time")
			}
			s.Created, *created = time.Unix(int64(binary.BigEndian.Uint32(v)), 0).UTC(), true
		case subSigExpires:
			if len(v) == 4 {
				s.SigExpires = time.Duration(binary.BigEndian.Uint32(v)) * time.Second
			}
		case subKeyExpires:
			if len(v) == 4 {
				s.KeyExpires = time.Duration(binary.BigEndian.Uint32(v)) * time.Second
			}
		case subIssuerKeyID:
			if len(v) == 8 {
				s.IssuerKeyID = binary.BigEndian.Uint64(v)
			}
		case subIssuerFP:
			if len(v) == 21 && v[0] == 4 {
				s.IssuerFP = bytes.Clone(v[1:])
			}
		case subKeyFlags:
			if len(v) > 0 {
				s.KeyFlags, s.HasKeyFlags = v[0], true
			}
		case subPrimaryUserID:
			s.PrimaryUID = len(v) == 1 && v[0] != 0
		case subEmbedded:
			emb, err := parseSignature(v)
			if err != nil && crit {
				return err
			}
			s.Embedded = emb
		case subPrefSymmetric, subPrefHash, subFeatures, 4, 5, 6, 7, 10, 12, 20, 22, 23, 24, 26, 28, 29, 31, 34, 35, 37, 38, 39:
			// Known, without meaning for wdyapt.
		default:
			if crit {
				return fmt.Errorf("signature with unknown critical subpacket %d", typ)
			}
		}
	}
	return nil
}

// Expired reports whether the signature has expired at time t.
func (s *Signature) expiredAt(t time.Time) bool {
	return s.SigExpires > 0 && !t.Before(s.Created.Add(s.SigExpires))
}

// digest computes the hash over the signed data and the hashed part of the
// signature including the trailer.
func (s *Signature) digest(parts ...[]byte) ([]byte, crypto.Hash, error) {
	h, ch, err := newHash(s.HashAlgo)
	if err != nil {
		return nil, 0, err
	}
	for _, p := range parts {
		h.Write(p)
	}
	h.Write(s.hashed)
	trailer := []byte{4, 0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(s.hashed)))
	h.Write(trailer)
	return h.Sum(nil), ch, nil
}

// strongHash reports whether a hash is allowed for signatures. SHA-1 and
// MD5 are rejected, as sqv does.
func strongHash(id byte) bool {
	switch id {
	case hashSHA224, hashSHA256, hashSHA384, hashSHA512:
		return true
	}
	return false
}

// verify verifies the signature over parts with the key pub.
func (s *Signature) verify(pub *PublicKey, parts ...[]byte) error {
	if !strongHash(s.HashAlgo) {
		return fmt.Errorf("signature uses the weak or unknown hash algorithm %d; SHA-224, SHA-256, SHA-384 and SHA-512 are accepted", s.HashAlgo)
	}
	if s.PubAlgo != pub.Algo && !(isRSA(s.PubAlgo) && isRSA(pub.Algo)) {
		return fmt.Errorf("signature algorithm %d does not match key %s", s.PubAlgo, pub.Fingerprint)
	}
	digest, ch, err := s.digest(parts...)
	if err != nil {
		return err
	}
	if digest[0] != s.left16[0] || digest[1] != s.left16[1] {
		return fmt.Errorf("signature by %s does not match the data", pub.Fingerprint)
	}
	switch {
	case pub.rsa != nil && s.rsaSig != nil:
		sig := leftPad(s.rsaSig, (pub.rsa.N.BitLen()+7)/8)
		if err := rsa.VerifyPKCS1v15(pub.rsa, ch, digest, sig); err != nil {
			return fmt.Errorf("bad RSA signature by %s", pub.Fingerprint)
		}
	case pub.ed25519 != nil && s.edR != nil:
		if len(s.edR) > 32 || len(s.edS) > 32 {
			return fmt.Errorf("broken Ed25519 signature by %s", pub.Fingerprint)
		}
		sig := make([]byte, 0, 64)
		sig = append(append(sig, leftPad(s.edR, 32)...), leftPad(s.edS, 32)...)
		if !ed25519.Verify(pub.ed25519, digest, sig) {
			return fmt.Errorf("bad Ed25519 signature by %s", pub.Fingerprint)
		}
	default:
		return fmt.Errorf("%w: algorithm %d", errUnsupportedSig, s.PubAlgo)
	}
	return nil
}

func isRSA(a byte) bool { return a == algoRSA || a == algoRSASign }

// subpacket builds a subpacket.
func subpacket(typ byte, v []byte) []byte {
	n := len(v) + 1
	var out []byte
	switch {
	case n < 192:
		out = []byte{byte(n)}
	case n < 8384:
		m := n - 192
		out = []byte{byte(m>>8) + 192, byte(m)}
	default:
		out = []byte{255, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	out = append(out, typ)
	return append(out, v...)
}

// sign creates a signature of type typ with key over parts. extra are
// additional hashed subpackets.
func sign(key *PrivateKey, typ byte, t time.Time, extra []byte, parts ...[]byte) (*Signature, error) {
	if !key.Unlocked() {
		return nil, fmt.Errorf("key %s is locked", key.Fingerprint)
	}
	var hashedSub []byte
	hashedSub = append(hashedSub, subpacket(subCreated, binary.BigEndian.AppendUint32(nil, uint32(t.Unix())))...)
	hashedSub = append(hashedSub, subpacket(subIssuerFP, append([]byte{4}, key.Fingerprint[:]...))...)
	hashedSub = append(hashedSub, extra...)
	algo := key.Algo
	if isRSA(algo) {
		algo = algoRSA
	}
	s := &Signature{Type: typ, PubAlgo: algo, HashAlgo: hashSHA512, Created: time.Unix(t.Unix(), 0).UTC(), IssuerKeyID: key.KeyID()}
	s.hashed = append([]byte{4, typ, algo, hashSHA512, byte(len(hashedSub) >> 8), byte(len(hashedSub))}, hashedSub...)
	digest, ch, err := s.digest(parts...)
	if err != nil {
		return nil, err
	}
	copy(s.left16[:], digest[:2])
	var material []byte
	switch {
	case key.rsa != nil:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.rsa, ch, digest)
		if err != nil {
			return nil, err
		}
		s.rsaSig = sig
		material = mpi(sig)
	case key.Algo == algoEd25519:
		sig := ed25519.Sign(key.ed25519, digest)
		s.edR, s.edS = sig[:32], sig[32:]
		material = sig
	default:
		sig := ed25519.Sign(key.ed25519, digest)
		s.edR, s.edS = sig[:32], sig[32:]
		material = append(mpi(sig[:32]), mpi(sig[32:])...)
	}
	unhashed := subpacket(subIssuerKeyID, binary.BigEndian.AppendUint64(nil, key.KeyID()))
	body := bytes.Clone(s.hashed)
	body = append(body, byte(len(unhashed)>>8), byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, s.left16[:]...)
	s.raw = append(body, material...)
	return s, nil
}

// packet returns the signature as a packet.
func (s *Signature) packet() []byte { return writePacket(tagSignature, s.raw) }
