package openpgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// Key is a primary key or subkey together with what its verified
// self-signatures say about it.
type Key struct {
	Public  *PublicKey
	Private *PrivateKey // nil without secret part
	Primary bool
	// Flags are the key flags of the valid self-signature; without flags the
	// algorithm decides (HasFlags false).
	Flags    byte
	HasFlags bool
	// Expires is the expiry; zero means never.
	Expires time.Time
	Revoked bool
	// Bound reports a valid self-signature or binding signature; Problem
	// says why not.
	Bound   bool
	Problem string
	// boundAt is the creation time of the valid binding; the newest counts.
	boundAt time.Time

	packets []packet // signature packets after the key, for the export
}

// Capabilities describes the capabilities like gpg: C, S, E, A.
func (k *Key) Capabilities() string {
	f := k.Flags
	if !k.HasFlags {
		switch k.Public.Algo {
		case algoECDH, algoX25519, algoX448, algoElgamal, algoRSAEncrypt:
			f = flagEncryptComms | flagEncryptStore
		default:
			f = flagSign
			if k.Primary {
				f |= flagCertify
			}
		}
	}
	var out []byte
	for _, c := range []struct {
		flag byte
		name byte
	}{{flagCertify, 'C'}, {flagSign, 'S'}, {flagEncryptComms | flagEncryptStore, 'E'}, {flagAuthenticate, 'A'}} {
		if f&c.flag != 0 {
			out = append(out, c.name)
		}
	}
	return string(out)
}

// canSignData reports whether the key may sign data.
func (k *Key) canSignData() bool {
	if k.HasFlags {
		return k.Flags&flagSign != 0
	}
	return k.Public.CanSign() && (k.Primary || k.Public.Algo == algoRSASign)
}

// validAt reports whether the key is valid at time t.
func (k *Key) validAt(t time.Time) error {
	switch {
	case !k.Bound:
		return fmt.Errorf("key %s is not bound to its primary key: %s", k.Public.Fingerprint, k.Problem)
	case k.Revoked:
		return fmt.Errorf("key %s is revoked", k.Public.Fingerprint)
	case t.Before(k.Public.Created):
		return fmt.Errorf("key %s was created after %s", k.Public.Fingerprint, t.Format(time.RFC3339))
	case !k.Expires.IsZero() && !t.Before(k.Expires):
		return fmt.Errorf("key %s expired on %s", k.Public.Fingerprint, k.Expires.Format(time.RFC3339))
	}
	return nil
}

// UserID is a user ID with a valid self-signature.
type UserID struct {
	Name    string
	Valid   bool
	Primary bool
	packets []packet // the self-signatures, for the export
}

// Entity is a transferable key: primary key, user IDs and subkeys.
type Entity struct {
	Primary *Key
	UserIDs []*UserID
	Subkeys []*Key
}

// Fingerprint is the fingerprint of the primary key.
func (e *Entity) Fingerprint() Fingerprint { return e.Primary.Public.Fingerprint }

// Keys returns the primary key and the subkeys.
func (e *Entity) Keys() []*Key { return append([]*Key{e.Primary}, e.Subkeys...) }

// HasSecret reports whether a key has a usable secret part.
func (e *Entity) HasSecret() bool {
	for _, k := range e.Keys() {
		if k.Private != nil && !k.Private.Stub {
			return true
		}
	}
	return false
}

// ReadKeys reads all keys from r, binary or in ASCII armors, as GnuPG or
// wdyapt write them. Self-signatures and bindings are verified; whatever they
// do not cover counts as not bound (R-KEY-USE-GNUPG-KEYS).
func ReadKeys(r io.Reader) ([]*Entity, error) {
	data, err := readAll(r, 16<<20)
	if err != nil {
		return nil, err
	}
	raw, err := unarmorAll(data)
	if err != nil {
		return nil, err
	}
	packets, err := readPackets(raw)
	if err != nil {
		return nil, err
	}
	var all []*Entity
	var cur *Entity
	var last *[]packet // where following signatures belong
	for _, p := range packets {
		switch p.tag {
		case tagPublicKey, tagSecretKey:
			if cur != nil {
				all = append(all, cur)
			}
			k, err := readKey(p)
			if err != nil {
				return nil, err
			}
			k.Primary = true
			cur = &Entity{Primary: k}
			last = &k.packets
		case tagPublicSubkey, tagSecretSubkey:
			if cur == nil {
				return nil, fmt.Errorf("subkey without primary key")
			}
			k, err := readKey(p)
			if err != nil {
				return nil, err
			}
			cur.Subkeys = append(cur.Subkeys, k)
			last = &k.packets
		case tagUserID:
			if cur == nil {
				return nil, fmt.Errorf("user ID without primary key")
			}
			u := &UserID{Name: string(p.body)}
			cur.UserIDs = append(cur.UserIDs, u)
			u.packets = []packet{p}
			last = &u.packets
		case tagUserAttribute:
			last = nil
		case tagSignature:
			if last != nil {
				*last = append(*last, p)
			}
		case tagTrust, tagMarker:
		default:
			return nil, fmt.Errorf("unexpected OpenPGP packet %d in a key", p.tag)
		}
	}
	if cur != nil {
		all = append(all, cur)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no OpenPGP key found")
	}
	for _, e := range all {
		e.check()
	}
	return all, nil
}

func readKey(p packet) (*Key, error) {
	if p.tag == tagSecretKey || p.tag == tagSecretSubkey {
		priv, err := parseSecretKey(p.body)
		if err != nil {
			return nil, err
		}
		return &Key{Public: priv.PublicKey, Private: priv}, nil
	}
	pub, rest, err := parsePublicKey(p.body)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("key %s: unexpected data after the public key", pub.Fingerprint)
	}
	return &Key{Public: pub}, nil
}

// check verifies all self-signatures and applies what they say.
func (e *Entity) check() {
	pk := e.Primary.Public
	now := time.Now()
	e.Primary.Problem = "no valid self-signature on a user ID or the key"
	// Direct signatures and revocations on the primary key.
	for _, p := range e.Primary.packets {
		s, err := parseSignature(p.body)
		if err != nil || !issuedBy(s, pk) {
			continue
		}
		switch s.Type {
		case sigKeyRevocation:
			if s.verify(pk, pk.hashPrefix()) == nil {
				e.Primary.Revoked = true
			}
		case sigDirectKey:
			if s.verify(pk, pk.hashPrefix()) == nil && !s.expiredAt(now) {
				e.Primary.apply(s)
			}
		}
	}
	for _, u := range e.UserIDs {
		uid := u.packets[0].body
		prefix := append([]byte{0xB4}, binary.BigEndian.AppendUint32(nil, uint32(len(uid)))...)
		for _, p := range u.packets[1:] {
			s, err := parseSignature(p.body)
			if err != nil || !issuedBy(s, pk) || s.Type < sigCertGeneric || s.Type > sigCertPositive {
				continue
			}
			if err := s.verify(pk, pk.hashPrefix(), prefix, uid); err != nil {
				e.Primary.Problem = err.Error()
				continue
			}
			if s.expiredAt(now) {
				continue
			}
			u.Valid = true
			u.Primary = u.Primary || s.PrimaryUID
			e.Primary.apply(s)
		}
	}
	for _, sub := range e.Subkeys {
		sub.Problem = "no valid binding signature"
		for _, p := range sub.packets {
			s, err := parseSignature(p.body)
			if err != nil || !issuedBy(s, pk) {
				continue
			}
			switch s.Type {
			case sigSubkeyRevocation:
				if s.verify(pk, pk.hashPrefix(), sub.Public.hashPrefix()) == nil {
					sub.Revoked = true
				}
			case sigSubkeyBinding:
				if err := s.verify(pk, pk.hashPrefix(), sub.Public.hashPrefix()); err != nil {
					sub.Problem = err.Error()
					continue
				}
				if s.expiredAt(now) {
					continue
				}
				// A signing subkey must confirm the primary key with an
				// embedded back signature.
				if s.HasKeyFlags && s.KeyFlags&flagSign != 0 {
					emb := s.Embedded
					if emb == nil || emb.Type != sigPrimaryBinding {
						sub.Problem = "signing subkey without primary key binding signature"
						continue
					}
					if err := emb.verify(sub.Public, pk.hashPrefix(), sub.Public.hashPrefix()); err != nil {
						sub.Problem = "primary key binding signature: " + err.Error()
						continue
					}
				}
				sub.apply(s)
			}
		}
	}
	if !e.Primary.Bound {
		for _, sub := range e.Subkeys {
			sub.Bound, sub.Problem = false, "the primary key is not valid"
		}
	}
}

// issuedBy reports whether the signature comes from key pk, as far as it
// says.
func issuedBy(s *Signature, pk *PublicKey) bool {
	if s.IssuerFP != nil {
		return bytes.Equal(s.IssuerFP, pk.Fingerprint[:])
	}
	return s.IssuerKeyID == 0 || s.IssuerKeyID == pk.KeyID()
}

// apply takes flags and expiry from the newest valid self-signature.
func (k *Key) apply(s *Signature) {
	if k.Bound && s.Created.Before(k.boundAt) {
		return
	}
	k.Bound, k.Problem, k.boundAt = true, "", s.Created
	k.Flags, k.HasFlags = s.KeyFlags, s.HasKeyFlags
	k.Expires = time.Time{}
	if s.KeyExpires > 0 {
		k.Expires = k.Public.Created.Add(s.KeyExpires)
	}
}

// Unlock unlocks all protected secret parts with passphrase.
func (e *Entity) Unlock(passphrase []byte) error {
	var errs []error
	for _, k := range e.Keys() {
		if k.Private == nil || k.Private.Stub || !k.Public.CanSign() {
			continue
		}
		if err := k.Private.Unlock(passphrase); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SigningKey chooses the key with which e signs data at time t: primary key
// or subkey with the sign flag, a valid binding, not revoked, not expired,
// with a secret part; if there are several, the newest.
func (e *Entity) SigningKey(t time.Time) (*Key, error) {
	var candidates []*Key
	var reasons []string
	for _, k := range e.Keys() {
		switch {
		case !k.canSignData():
			continue
		case !k.Public.CanSign():
			reasons = append(reasons, fmt.Sprintf("%s: wdyapt cannot sign with %s", k.Public.Fingerprint, k.Public.AlgoName()))
		case k.Private == nil:
			reasons = append(reasons, fmt.Sprintf("%s: no secret part", k.Public.Fingerprint))
		case k.Private.Stub:
			reasons = append(reasons, fmt.Sprintf("%s: the secret part is not in the file", k.Public.Fingerprint))
		default:
			if err := k.validAt(t); err != nil {
				reasons = append(reasons, err.Error())
				continue
			}
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		if len(reasons) == 0 {
			reasons = append(reasons, "no key is allowed to sign")
		}
		return nil, fmt.Errorf("key %s cannot sign: %s", e.Fingerprint(), joinReasons(reasons))
	}
	slices.SortStableFunc(candidates, func(a, b *Key) int { return b.Public.Created.Compare(a.Public.Created) })
	return candidates[0], nil
}

func joinReasons(r []string) string {
	var b bytes.Buffer
	for i, s := range r {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(s)
	}
	return b.String()
}

// Export writes the public part of e in binary: primary key, user IDs and
// subkeys with their signatures, without secret parts
// (R-KEY-EXPORT-AND-SHOW).
func Export(e *Entity) []byte {
	var out []byte
	out = append(out, writePacket(tagPublicKey, e.Primary.Public.body)...)
	for _, p := range e.Primary.packets {
		out = append(out, writePacket(p.tag, p.body)...)
	}
	for _, u := range e.UserIDs {
		for _, p := range u.packets {
			out = append(out, writePacket(p.tag, p.body)...)
		}
	}
	for _, k := range e.Subkeys {
		out = append(out, writePacket(tagPublicSubkey, k.Public.body)...)
		for _, p := range k.packets {
			out = append(out, writePacket(p.tag, p.body)...)
		}
	}
	return out
}

// ExportArmored writes the public part in an ASCII armor.
func ExportArmored(e *Entity) []byte { return Armor(PublicKeyBlock, Export(e)) }

// Keyring holds the keys by which a published state may be signed.
type Keyring struct {
	entities []*Entity
}

// NewKeyring builds a keyring; secret parts are not needed.
func NewKeyring(entities ...*Entity) *Keyring {
	return &Keyring{entities: entities}
}

// Add adds keys.
func (k *Keyring) Add(entities ...*Entity) { k.entities = append(k.entities, entities...) }

// Entities returns the keys of the keyring.
func (k *Keyring) Entities() []*Entity { return k.entities }

// lookup finds the key that issued the signature.
func (k *Keyring) lookup(s *Signature) (*Entity, *Key) {
	for _, e := range k.entities {
		for _, key := range e.Keys() {
			fp := key.Public.Fingerprint
			if s.IssuerFP != nil && bytes.Equal(s.IssuerFP, fp[:]) || s.IssuerFP == nil && s.IssuerKeyID == fp.KeyID() {
				return e, key
			}
		}
	}
	return nil, nil
}
