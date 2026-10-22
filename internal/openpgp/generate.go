package openpgp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Generate creates a version 4 key with EdDSALegacy (Ed25519) as primary key
// with the capabilities certify and sign, and a user ID with a positive
// certification. expires 0 means never. EdDSALegacy instead of Ed25519 (27),
// because gpgv in Ubuntu 24.04 (GnuPG 2.4) does not know algorithm 27
// (R-KEY-GENERATE).
func Generate(userID string, created time.Time, expires time.Duration) (*Entity, error) {
	if strings.TrimSpace(userID) == "" || strings.ContainsAny(userID, "\n\r\x00") {
		return nil, errors.New("the user ID must be one line of text, e.g. \"Example APT <apt@example.com>\"")
	}
	if expires < 0 || expires/time.Second > 1<<32-1 {
		return nil, errors.New("invalid expiry")
	}
	created = time.Unix(created.Unix(), 0).UTC()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	body := encodePublicEd25519(created, pub)
	pk, rest, err := parsePublicKey(body)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("generated key does not parse: %v", err)
	}
	sk := &PrivateKey{PublicKey: pk, Usage: usagePlain, ed25519: priv}

	var extra []byte
	extra = append(extra, subpacket(subKeyFlags, []byte{flagCertify | flagSign})...)
	if expires > 0 {
		extra = append(extra, subpacket(subKeyExpires, binary.BigEndian.AppendUint32(nil, uint32(expires/time.Second)))...)
	}
	extra = append(extra, subpacket(subPrefSymmetric, []byte{symAES256, symAES128})...)
	extra = append(extra, subpacket(subPrefHash, []byte{hashSHA512, hashSHA256})...)
	extra = append(extra, subpacket(subFeatures, []byte{0x01})...)
	uid := []byte(userID)
	prefix := append([]byte{0xB4}, binary.BigEndian.AppendUint32(nil, uint32(len(uid)))...)
	cert, err := sign(sk, sigCertPositive, created, extra, pk.hashPrefix(), prefix, uid)
	if err != nil {
		return nil, err
	}
	e := &Entity{
		Primary: &Key{Public: pk, Private: sk, Primary: true},
		UserIDs: []*UserID{{Name: userID, packets: []packet{{tag: tagUserID, body: uid}, {tag: tagSignature, body: cert.raw}}}},
	}
	e.check()
	if !e.Primary.Bound {
		return nil, fmt.Errorf("generated key does not verify: %s", e.Primary.Problem)
	}
	return e, nil
}

// ExportSecret writes e with all secret parts in binary; protected with
// passphrase (AES-256, iterated and salted S2K with SHA-256), unprotected
// without one. All secret parts must be unlocked.
func ExportSecret(e *Entity, passphrase []byte) ([]byte, error) {
	var out []byte
	write := func(k *Key, secretTag, publicTag byte) error {
		if k.Private == nil || k.Private.Stub || !k.Private.Unlocked() {
			if k.Private != nil && !k.Private.Stub && k.Public.CanSign() {
				return fmt.Errorf("key %s is locked", k.Public.Fingerprint)
			}
			out = append(out, writePacket(publicTag, k.Public.body)...)
			return nil
		}
		body, err := k.Private.serializeSecret(passphrase)
		if err != nil {
			return err
		}
		out = append(out, writePacket(secretTag, body)...)
		return nil
	}
	if err := write(e.Primary, tagSecretKey, tagPublicKey); err != nil {
		return nil, err
	}
	for _, p := range e.Primary.packets {
		out = append(out, writePacket(p.tag, p.body)...)
	}
	for _, u := range e.UserIDs {
		for _, p := range u.packets {
			out = append(out, writePacket(p.tag, p.body)...)
		}
	}
	for _, k := range e.Subkeys {
		if err := write(k, tagSecretSubkey, tagPublicSubkey); err != nil {
			return nil, err
		}
		for _, p := range k.packets {
			out = append(out, writePacket(p.tag, p.body)...)
		}
	}
	return out, nil
}

// ExportSecretArmored writes ExportSecret in an ASCII armor.
func ExportSecretArmored(e *Entity, passphrase []byte) ([]byte, error) {
	data, err := ExportSecret(e, passphrase)
	if err != nil {
		return nil, err
	}
	return Armor(PrivateKeyBlock, data), nil
}
