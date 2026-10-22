package ssh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// Key and signature algorithms.
const (
	KeyEd25519   = "ssh-ed25519"
	KeyECDSA256  = "ecdsa-sha2-nistp256"
	KeyECDSA384  = "ecdsa-sha2-nistp384"
	KeyECDSA521  = "ecdsa-sha2-nistp521"
	KeyRSA       = "ssh-rsa"
	SigRSASHA256 = "rsa-sha2-256"
	SigRSASHA512 = "rsa-sha2-512"
)

// PublicKey is a public key in SSH format.
type PublicKey interface {
	// Type is the key type, such as "ssh-ed25519" or "ssh-rsa".
	Type() string
	// Marshal is the blob as in RFC 4253, 6.6.
	Marshal() []byte
	// Verify checks sig (blob of algorithm and signature) over data.
	Verify(data, sig []byte) error
}

// Signer can sign with a private key.
type Signer interface {
	PublicKey() PublicKey
	// Sign signs data with the signature algorithm algo and returns the
	// signature blob.
	Sign(data []byte, algo string) ([]byte, error)
}

// Fingerprint is the fingerprint as in OpenSSH: "SHA256:" and Base64
// without padding over the blob.
func Fingerprint(k PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// AuthorizedKey writes the key as "type base64", as in
// known_hosts.
func AuthorizedKey(k PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

// sigAlgos returns the signature algorithms of a key type.
func sigAlgos(keyType string) []string {
	if keyType == KeyRSA {
		return []string{SigRSASHA512, SigRSASHA256}
	}
	return []string{keyType}
}

// keyTypeOf returns the key type of a host key algorithm.
func keyTypeOf(algo string) string {
	if algo == SigRSASHA256 || algo == SigRSASHA512 {
		return KeyRSA
	}
	return algo
}

// ParsePublicKey reads a key blob.
func ParsePublicKey(blob []byte) (PublicKey, error) {
	p := newParser(blob)
	typ := p.text()
	switch typ {
	case KeyEd25519:
		k := p.string()
		if err := p.done(); err != nil || len(k) != ed25519.PublicKeySize {
			return nil, errors.New("ssh: malformed ed25519 key")
		}
		return ed25519Key(bytes.Clone(k)), nil
	case KeyECDSA256, KeyECDSA384, KeyECDSA521:
		curveName := p.text()
		point := p.string()
		if err := p.done(); err != nil || curveName != typ[len("ecdsa-sha2-"):] {
			return nil, errors.New("ssh: malformed ecdsa key")
		}
		curve := curveOf(typ)
		x, y := elliptic.Unmarshal(curve, point) //nolint:staticcheck // needed for ecdsa.PublicKey
		if x == nil {
			return nil, errors.New("ssh: invalid ecdsa point")
		}
		return &ecdsaKey{typ: typ, key: &ecdsa.PublicKey{Curve: curve, X: x, Y: y}}, nil
	case KeyRSA:
		e := p.mpint()
		n := p.mpint()
		if err := p.done(); err != nil {
			return nil, errors.New("ssh: malformed rsa key")
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 {
			return nil, errors.New("ssh: unusable rsa exponent")
		}
		if n.BitLen() < 2048 {
			return nil, fmt.Errorf("ssh: rsa key with %d bits is too short; at least 2048 are needed", n.BitLen())
		}
		return &rsaKey{&rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
	}
	if p.err != nil {
		return nil, errShort
	}
	return nil, fmt.Errorf("ssh: unsupported key type %q", typ)
}

func curveOf(typ string) elliptic.Curve {
	switch typ {
	case KeyECDSA384:
		return elliptic.P384()
	case KeyECDSA521:
		return elliptic.P521()
	}
	return elliptic.P256()
}

func hashOf(typ string) crypto.Hash {
	switch typ {
	case KeyECDSA384:
		return crypto.SHA384
	case KeyECDSA521, SigRSASHA512:
		return crypto.SHA512
	}
	return crypto.SHA256
}

func digest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	s := sha256.Sum256(data)
	return s[:]
}

// splitSig splits a signature blob into algorithm and signature.
func splitSig(sig []byte) (string, []byte, error) {
	p := newParser(sig)
	algo, blob := p.text(), p.string()
	if err := p.done(); err != nil {
		return "", nil, errors.New("ssh: malformed signature")
	}
	return algo, blob, nil
}

type ed25519Key ed25519.PublicKey

func (k ed25519Key) Type() string { return KeyEd25519 }
func (k ed25519Key) Marshal() []byte {
	return (&builder{}).text(KeyEd25519).string(k).b
}
func (k ed25519Key) Verify(data, sig []byte) error {
	algo, blob, err := splitSig(sig)
	if err != nil {
		return err
	}
	if algo != KeyEd25519 || len(blob) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(k), data, blob) {
		return errors.New("ssh: bad ed25519 signature")
	}
	return nil
}

type ecdsaKey struct {
	typ string
	key *ecdsa.PublicKey
}

func (k *ecdsaKey) Type() string { return k.typ }
func (k *ecdsaKey) Marshal() []byte {
	point := elliptic.Marshal(k.key.Curve, k.key.X, k.key.Y) //nolint:staticcheck // point uncompressed, as SSH wants it
	return (&builder{}).text(k.typ).text(k.typ[len("ecdsa-sha2-"):]).string(point).b
}
func (k *ecdsaKey) Verify(data, sig []byte) error {
	algo, blob, err := splitSig(sig)
	if err != nil {
		return err
	}
	if algo != k.typ {
		return fmt.Errorf("ssh: signature algorithm %q for a %s key", algo, k.typ)
	}
	p := newParser(blob)
	r, s := p.mpint(), p.mpint()
	if err := p.done(); err != nil {
		return errors.New("ssh: malformed ecdsa signature")
	}
	if !ecdsa.Verify(k.key, digest(hashOf(k.typ), data), r, s) {
		return errors.New("ssh: bad ecdsa signature")
	}
	return nil
}

type rsaKey struct{ key *rsa.PublicKey }

func (k *rsaKey) Type() string { return KeyRSA }
func (k *rsaKey) Marshal() []byte {
	return (&builder{}).text(KeyRSA).mpint(big.NewInt(int64(k.key.E))).mpint(k.key.N).b
}
func (k *rsaKey) Verify(data, sig []byte) error {
	algo, blob, err := splitSig(sig)
	if err != nil {
		return err
	}
	if algo != SigRSASHA256 && algo != SigRSASHA512 {
		return fmt.Errorf("ssh: rsa signature algorithm %q is not accepted; only rsa-sha2-256 and rsa-sha2-512", algo)
	}
	h := hashOf(algo)
	if err := rsa.VerifyPKCS1v15(k.key, h, digest(h, data), blob); err != nil {
		return errors.New("ssh: bad rsa signature")
	}
	return nil
}

// NewSigner turns a private key from the standard library
// (ed25519.PrivateKey, *ecdsa.PrivateKey, *rsa.PrivateKey) into a Signer.
func NewSigner(key crypto.Signer) (Signer, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return &keySigner{key: k, pub: ed25519Key(k.Public().(ed25519.PublicKey))}, nil
	case *ecdsa.PrivateKey:
		var typ string
		switch k.Curve {
		case elliptic.P256():
			typ = KeyECDSA256
		case elliptic.P384():
			typ = KeyECDSA384
		case elliptic.P521():
			typ = KeyECDSA521
		default:
			return nil, errors.New("ssh: unsupported ecdsa curve")
		}
		return &keySigner{key: k, pub: &ecdsaKey{typ: typ, key: &k.PublicKey}}, nil
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("ssh: rsa keys need at least 2048 bits")
		}
		return &keySigner{key: k, pub: &rsaKey{&k.PublicKey}}, nil
	}
	return nil, fmt.Errorf("ssh: unsupported private key %T", key)
}

type keySigner struct {
	key crypto.Signer
	pub PublicKey
}

func (s *keySigner) PublicKey() PublicKey { return s.pub }

func (s *keySigner) Sign(data []byte, algo string) ([]byte, error) {
	switch k := s.key.(type) {
	case ed25519.PrivateKey:
		if algo != KeyEd25519 {
			return nil, fmt.Errorf("ssh: cannot sign %s with an ed25519 key", algo)
		}
		return (&builder{}).text(algo).string(ed25519.Sign(k, data)).b, nil
	case *ecdsa.PrivateKey:
		if algo != s.pub.Type() {
			return nil, fmt.Errorf("ssh: cannot sign %s with a %s key", algo, s.pub.Type())
		}
		r, ss, err := ecdsa.Sign(rand.Reader, k, digest(hashOf(algo), data))
		if err != nil {
			return nil, err
		}
		inner := (&builder{}).mpint(r).mpint(ss).b
		return (&builder{}).text(algo).string(inner).b, nil
	case *rsa.PrivateKey:
		if algo != SigRSASHA256 && algo != SigRSASHA512 {
			return nil, fmt.Errorf("ssh: rsa signs only with rsa-sha2-256 or rsa-sha2-512, not %s", algo)
		}
		h := hashOf(algo)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, h, digest(h, data))
		if err != nil {
			return nil, err
		}
		return (&builder{}).text(algo).string(sig).b, nil
	}
	return nil, errors.New("ssh: unsupported key")
}
