package openpgp

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// Protection types of the secret part (RFC 9580, 3.7.2).
const (
	usagePlain    = 0
	usageAEAD     = 253
	usageCFBSHA1  = 254
	usageCFBCheck = 255
)

// Symmetric ciphers and hashes that occur in S2K.
const (
	symAES128 = 7
	symAES192 = 8
	symAES256 = 9

	hashSHA1   = 2
	hashSHA256 = 8
	hashSHA384 = 9
	hashSHA512 = 10
	hashSHA224 = 11
)

// ErrPassphrase reports a wrong passphrase.
var ErrPassphrase = errors.New("wrong passphrase for the secret key")

// ErrNoPassphrase reports a protected key without passphrase.
var ErrNoPassphrase = errors.New("the secret key is protected by a passphrase, but none was given")

// PrivateKey is the secret part of a key.
type PrivateKey struct {
	*PublicKey
	// Usage is the protection type: 0 unprotected, 254 or 255 with passphrase.
	Usage byte
	// Stub reports a key without secret part, as GnuPG writes it for the
	// primary key with --export-secret-subkeys.
	Stub bool

	sym       byte
	s2k       *s2k
	iv        []byte
	encrypted []byte
	plain     []byte // the secret numbers, unprotected or unlocked

	rsa     *rsa.PrivateKey
	ed25519 ed25519.PrivateKey
}

// Protected reports whether the secret part needs a passphrase.
func (k *PrivateKey) Protected() bool { return k.Usage != usagePlain && !k.Stub }

// Unlocked reports whether the key can sign.
func (k *PrivateKey) Unlocked() bool { return k.rsa != nil || k.ed25519 != nil }

// s2k is a string-to-key specifier (RFC 9580, 3.7.1).
type s2k struct {
	typ   byte
	hash  byte
	salt  []byte
	count int
	raw   []byte
}

// parseSecretKey reads a secret key; the secret part follows the public
// part.
func parseSecretKey(body []byte) (*PrivateKey, error) {
	pub, rest, err := parsePublicKey(body)
	if err != nil {
		return nil, err
	}
	k := &PrivateKey{PublicKey: pub}
	r := &reader{b: rest}
	k.Usage = r.byte()
	switch k.Usage {
	case usagePlain:
		k.plain = r.b
	case usageCFBSHA1, usageCFBCheck:
		k.sym = r.byte()
		spec, err := parseS2K(r)
		if err != nil {
			return nil, err
		}
		k.s2k = spec
		if spec.typ == 101 {
			k.Stub = true
			return k, nil
		}
		k.iv = r.bytes(blockSize(k.sym))
		k.encrypted = r.b
	case usageAEAD:
		return nil, fmt.Errorf("key %s: secret keys protected with AEAD are not supported; export the key with GnuPG's default protection or without passphrase", pub.Fingerprint)
	default:
		return nil, fmt.Errorf("key %s: legacy secret key protection %d is not supported; export the key again with a current GnuPG", pub.Fingerprint, k.Usage)
	}
	if r.err != nil {
		return nil, fmt.Errorf("key %s: broken secret key: %w", pub.Fingerprint, r.err)
	}
	if k.Usage == usagePlain && k.CanSign() {
		if err := k.parseSecret(k.plain, true); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func parseS2K(r *reader) (*s2k, error) {
	start := r.b
	s := &s2k{typ: r.byte()}
	switch s.typ {
	case 0:
		s.hash = r.byte()
	case 1:
		s.hash = r.byte()
		s.salt = r.bytes(8)
	case 3:
		s.hash = r.byte()
		s.salt = r.bytes(8)
		c := int(r.byte())
		s.count = (16 + (c & 15)) << ((c >> 4) + 6)
	case 4:
		return nil, fmt.Errorf("secret keys protected with Argon2 are not supported; export the key with GnuPG's default protection or without passphrase")
	case 101:
		s.hash = r.byte()
		if gnu := r.bytes(3); r.err == nil && string(gnu) != "GNU" {
			return nil, fmt.Errorf("unknown S2K extension")
		}
		r.byte() // 1: no secret part, 2: on a card
	default:
		return nil, fmt.Errorf("unknown S2K type %d", s.typ)
	}
	if r.err != nil {
		return nil, r.err
	}
	s.raw = bytes.Clone(start[:len(start)-len(r.b)])
	return s, nil
}

func newHash(id byte) (hash.Hash, crypto.Hash, error) {
	switch id {
	case hashSHA1:
		return sha1.New(), crypto.SHA1, nil
	case hashSHA256:
		return sha256.New(), crypto.SHA256, nil
	case hashSHA384:
		return sha512.New384(), crypto.SHA384, nil
	case hashSHA512:
		return sha512.New(), crypto.SHA512, nil
	case hashSHA224:
		return sha256.New224(), crypto.SHA224, nil
	}
	return nil, 0, fmt.Errorf("unsupported hash algorithm %d", id)
}

func keySize(sym byte) int {
	switch sym {
	case symAES128:
		return 16
	case symAES192:
		return 24
	case symAES256:
		return 32
	}
	return 0
}

func blockSize(sym byte) int {
	if keySize(sym) > 0 {
		return aes.BlockSize
	}
	return 8
}

// derive derives the key from the passphrase (RFC 9580, 3.7.1). For keys
// longer than one hash, further hashes run with prepended zero bytes.
func (s *s2k) derive(passphrase []byte, size int) ([]byte, error) {
	var out []byte
	for i := 0; len(out) < size; i++ {
		h, _, err := newHash(s.hash)
		if err != nil {
			return nil, err
		}
		h.Write(make([]byte, i))
		data := append(bytes.Clone(s.salt), passphrase...)
		switch s.typ {
		case 0, 1:
			h.Write(data)
		case 3:
			count := max(s.count, len(data))
			for count > 0 {
				n := min(count, len(data))
				h.Write(data[:n])
				count -= n
			}
		}
		out = h.Sum(out)
	}
	return out[:size], nil
}

// Unlock decrypts the secret part with passphrase. An unprotected key needs
// none.
func (k *PrivateKey) Unlock(passphrase []byte) error {
	if k.Unlocked() || !k.CanSign() {
		return nil
	}
	if k.Stub {
		return fmt.Errorf("key %s has no secret part (exported with --export-secret-subkeys or kept on a card)", k.Fingerprint)
	}
	if k.Usage == usagePlain {
		return k.parseSecret(k.plain, true)
	}
	if len(passphrase) == 0 {
		return fmt.Errorf("key %s: %w", k.Fingerprint, ErrNoPassphrase)
	}
	size := keySize(k.sym)
	if size == 0 {
		return fmt.Errorf("key %s: symmetric algorithm %d is not supported; export the key with AES", k.Fingerprint, k.sym)
	}
	key, err := k.s2k.derive(passphrase, size)
	if err != nil {
		return fmt.Errorf("key %s: %w", k.Fingerprint, err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	plain := make([]byte, len(k.encrypted))
	//lint:ignore SA1019 OpenPGP mandates CFB for protected keys.
	cipher.NewCFBDecrypter(block, k.iv).XORKeyStream(plain, k.encrypted)
	switch k.Usage {
	case usageCFBSHA1:
		if len(plain) < sha1.Size {
			return fmt.Errorf("key %s: %w", k.Fingerprint, ErrPassphrase)
		}
		data, sum := plain[:len(plain)-sha1.Size], plain[len(plain)-sha1.Size:]
		want := sha1.Sum(data)
		if subtle.ConstantTimeCompare(sum, want[:]) != 1 {
			return fmt.Errorf("key %s: %w", k.Fingerprint, ErrPassphrase)
		}
		return k.parseSecret(data, false)
	default:
		if err := k.parseSecret(plain, true); err != nil {
			return fmt.Errorf("key %s: %w", k.Fingerprint, ErrPassphrase)
		}
		return nil
	}
}

// parseSecret reads the secret numbers; withChecksum verifies the two-byte
// checksum after them.
func (k *PrivateKey) parseSecret(data []byte, withChecksum bool) error {
	r := &reader{b: data}
	switch k.Algo {
	case algoRSA, algoRSASign, algoRSAEncrypt:
		d, p, q, _ := r.mpi(), r.mpi(), r.mpi(), r.mpi()
		if r.err != nil {
			break
		}
		priv := &rsa.PrivateKey{
			PublicKey: *k.PublicKey.rsa,
			D:         new(big.Int).SetBytes(d),
			Primes:    []*big.Int{new(big.Int).SetBytes(p), new(big.Int).SetBytes(q)},
		}
		if err := priv.Validate(); err != nil {
			return fmt.Errorf("key %s: broken RSA secret key: %w", k.Fingerprint, err)
		}
		priv.Precompute()
		k.rsa = priv
	case algoEdDSALegacy:
		seed := r.mpi()
		if r.err != nil {
			break
		}
		if len(seed) > 32 {
			return fmt.Errorf("key %s: broken Ed25519 secret key", k.Fingerprint)
		}
		priv := ed25519.NewKeyFromSeed(leftPad(seed, 32))
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), k.PublicKey.ed25519) {
			return fmt.Errorf("key %s: the secret key does not fit the public key", k.Fingerprint)
		}
		k.ed25519 = priv
	case algoEd25519:
		seed := r.bytes(32)
		if r.err != nil {
			break
		}
		priv := ed25519.NewKeyFromSeed(seed)
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), k.PublicKey.ed25519) {
			return fmt.Errorf("key %s: the secret key does not fit the public key", k.Fingerprint)
		}
		k.ed25519 = priv
	default:
		return nil
	}
	if r.err != nil {
		return fmt.Errorf("key %s: broken secret key", k.Fingerprint)
	}
	if withChecksum {
		used := data[:len(data)-len(r.b)]
		sum := uint16(0)
		for _, b := range used {
			sum += uint16(b)
		}
		if len(r.b) < 2 || uint16(r.b[0])<<8|uint16(r.b[1]) != sum {
			return fmt.Errorf("key %s: secret key checksum mismatch", k.Fingerprint)
		}
	}
	return nil
}

// secretMPIs are the secret numbers of an unlocked key.
func (k *PrivateKey) secretMPIs() []byte {
	switch {
	case k.rsa != nil:
		p, q := k.rsa.Primes[0], k.rsa.Primes[1]
		u := new(big.Int).ModInverse(p, q)
		var b []byte
		for _, v := range []*big.Int{k.rsa.D, p, q, u} {
			b = append(b, mpiInt(v)...)
		}
		return b
	case k.Algo == algoEd25519:
		return bytes.Clone(k.ed25519.Seed())
	default:
		return mpi(k.ed25519.Seed())
	}
}

// serializeSecret builds the content of the secret key packet: unprotected
// or protected with passphrase (AES-256, iterated and salted S2K with
// SHA-256, SHA-1 over the plaintext).
func (k *PrivateKey) serializeSecret(passphrase []byte) ([]byte, error) {
	if !k.Unlocked() {
		return nil, fmt.Errorf("key %s is locked", k.Fingerprint)
	}
	secret := k.secretMPIs()
	out := bytes.Clone(k.body)
	if len(passphrase) == 0 {
		sum := uint16(0)
		for _, b := range secret {
			sum += uint16(b)
		}
		out = append(out, usagePlain)
		out = append(out, secret...)
		return append(out, byte(sum>>8), byte(sum)), nil
	}
	salt := make([]byte, 8)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	const countByte = 0xF0
	spec := &s2k{typ: 3, hash: hashSHA256, salt: salt, count: (16 + (countByte & 15)) << ((countByte >> 4) + 6)}
	key, err := spec.derive(passphrase, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(secret)
	plain := append(bytes.Clone(secret), sum[:]...)
	enc := make([]byte, len(plain))
	//lint:ignore SA1019 OpenPGP mandates CFB for protected keys.
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(enc, plain)
	out = append(out, usageCFBSHA1, symAES256, 3, hashSHA256)
	out = append(out, salt...)
	out = append(out, countByte)
	out = append(out, iv...)
	return append(out, enc...), nil
}
