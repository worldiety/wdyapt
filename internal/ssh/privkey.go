package ssh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// errEncryptedKey explains why encrypted keys do not work.
var errEncryptedKey = errors.New("the private key is encrypted with a passphrase, which wdyapt cannot decrypt (it needs bcrypt and Blowfish, which the Go standard library lacks); load the key into ssh-agent instead, or use an unencrypted key kept in a protected CI variable")

// ParsePrivateKey reads a private key in OpenSSH format
// (openssh-key-v1, unencrypted) or as PEM (PKCS#8, PKCS#1, SEC1).
func ParsePrivateKey(data []byte) (Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block with a private key found")
	}
	if _, ok := block.Headers["Proc-Type"]; ok {
		return nil, errEncryptedKey
	}
	var key any
	var err error
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		key, err = parseOpenSSHKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		return nil, errEncryptedKey
	default:
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key %T", key)
	}
	return NewSigner(signer)
}

// parseOpenSSHKey reads openssh-key-v1 (OpenSSH's PROTOCOL.key).
func parseOpenSSHKey(b []byte) (any, error) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return nil, errors.New("not an OpenSSH private key")
	}
	r := newParser(b[len(magic):])
	cipherName, kdfName := r.text(), r.text()
	r.string()
	n := r.uint32()
	if r.err != nil {
		return nil, errors.New("broken OpenSSH private key")
	}
	if cipherName != "none" || kdfName != "none" {
		return nil, errEncryptedKey
	}
	if n != 1 {
		return nil, fmt.Errorf("the file holds %d keys; wdyapt reads files with exactly one", n)
	}
	r.string() // public key, also contained in the private part
	priv := newParser(r.string())
	if r.err != nil {
		return nil, errors.New("broken OpenSSH private key")
	}
	if c1, c2 := priv.uint32(), priv.uint32(); c1 != c2 {
		return nil, errors.New("broken OpenSSH private key: check values differ")
	}
	typ := priv.text()
	var key any
	switch typ {
	case KeyEd25519:
		pub, sk := priv.string(), priv.string()
		if priv.err != nil || len(pub) != ed25519.PublicKeySize || len(sk) != ed25519.PrivateKeySize {
			return nil, errors.New("broken ed25519 private key")
		}
		k := ed25519.NewKeyFromSeed(sk[:32])
		if !bytes.Equal(k.Public().(ed25519.PublicKey), pub) {
			return nil, errors.New("broken ed25519 private key: the public part does not match")
		}
		key = k
	case KeyECDSA256, KeyECDSA384, KeyECDSA521:
		priv.text()
		point, d := priv.string(), priv.mpint()
		if priv.err != nil {
			return nil, errors.New("broken ecdsa private key")
		}
		curve := curveOf(typ)
		k, err := ecdsa.ParseRawPrivateKey(curve, leftPadBytes(d.Bytes(), (curve.Params().BitSize+7)/8))
		if err != nil {
			return nil, fmt.Errorf("broken ecdsa private key: %w", err)
		}
		pub, err := k.PublicKey.Bytes()
		if err != nil || !bytes.Equal(pub, point) {
			return nil, errors.New("broken ecdsa private key: the public part does not match")
		}
		key = k
	case KeyRSA:
		nn, e, d, _, p, q := priv.mpint(), priv.mpint(), priv.mpint(), priv.mpint(), priv.mpint(), priv.mpint()
		if priv.err != nil || !e.IsInt64() {
			return nil, errors.New("broken rsa private key")
		}
		k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: nn, E: int(e.Int64())}, D: d, Primes: []*big.Int{p, q}}
		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("broken rsa private key: %w", err)
		}
		k.Precompute()
		key = k
	default:
		return nil, fmt.Errorf("unsupported private key type %q", typ)
	}
	return key, nil
}

func leftPadBytes(v []byte, n int) []byte {
	if len(v) >= n {
		return v
	}
	out := make([]byte, n)
	copy(out[n-len(v):], v)
	return out
}
