package openpgp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/dec"
	reqkey "github.com/worldiety/wdyapt/requirements/fun/key"
)

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fingerprints reads testdata/keys.txt: name and fingerprint per line.
func fingerprints(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(testdata(t, "keys.txt"))), "\n") {
		name, fp, _ := strings.Cut(line, " ")
		out[name] = fp
	}
	return out
}

func loadKey(t *testing.T, name string) *Entity {
	t.Helper()
	es, err := ReadKeys(bytes.NewReader(testdata(t, name)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(es) != 1 {
		t.Fatalf("%s: %d keys", name, len(es))
	}
	return es[0]
}

func TestArmorCRC(t *testing.T) {
	if crc24(nil) != 0xB704CE {
		t.Errorf("crc24 of nothing = %#x", crc24(nil))
	}
	data := bytes.Repeat([]byte("wdyapt"), 50)
	armored := Armor(SignatureBlock, data)
	for line := range strings.SplitSeq(string(armored), "\n") {
		if len(line) > 64 {
			t.Errorf("armor line longer than 64: %q", line)
		}
	}
	typ, body, _, err := Dearmor(armored)
	if err != nil || typ != SignatureBlock || !bytes.Equal(body, data) {
		t.Fatalf("round trip: %q %v", typ, err)
	}
	broken := bytes.Replace(armored, []byte("d2R5"), []byte("d2R6"), 1)
	if _, _, _, err := Dearmor(broken); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("changed armor accepted: %v", err)
	}
	spec.Verified(t, dec.RDecOpenpgpInProcess)
}

// Keys from GnuPG are read: fingerprints as gpg shows them, user IDs,
// algorithms, subkeys and protection.
func TestReadsGnuPGKeys(t *testing.T) {
	fps := fingerprints(t)
	colons := string(testdata(t, "fingerprints.txt"))
	for _, tc := range []struct {
		file, name, uid, algo string
		protected             bool
	}{
		{"ed25519.secret.asc", "ed25519", "Test Ed25519 <ed25519@example.com>", "ed25519 (EdDSA legacy)", false},
		{"protected.secret.asc", "protected", "Test Protected <protected@example.com>", "ed25519 (EdDSA legacy)", true},
		{"rsa3072.secret.asc", "rsa3072", "Test RSA <rsa@example.com>", "rsa3072", false},
		{"subkey.secret.asc", "subkey", "Test Subkey <subkey@example.com>", "ed25519 (EdDSA legacy)", false},
		{"ed25519.public.asc", "ed25519", "Test Ed25519 <ed25519@example.com>", "ed25519 (EdDSA legacy)", false},
		{"ed25519.public.gpg", "ed25519", "Test Ed25519 <ed25519@example.com>", "ed25519 (EdDSA legacy)", false},
	} {
		e := loadKey(t, tc.file)
		if got := e.Fingerprint().String(); got != fps[tc.name] {
			t.Errorf("%s: fingerprint %s, want %s", tc.file, got, fps[tc.name])
		}
		if len(e.UserIDs) != 1 || e.UserIDs[0].Name != tc.uid || !e.UserIDs[0].Valid {
			t.Errorf("%s: user IDs %+v", tc.file, e.UserIDs)
		}
		if e.Primary.Public.AlgoName() != tc.algo || !e.Primary.Bound {
			t.Errorf("%s: %s bound=%v (%s)", tc.file, e.Primary.Public.AlgoName(), e.Primary.Bound, e.Primary.Problem)
		}
		if p := e.Primary.Private; p != nil && p.Protected() != tc.protected {
			t.Errorf("%s: protected = %v", tc.file, p.Protected())
		}
		for _, k := range e.Keys() {
			if !strings.Contains(colons, "fpr:::::::::"+k.Public.Fingerprint.String()+":") {
				t.Errorf("%s: gpg does not list %s", tc.file, k.Public.Fingerprint)
			}
		}
	}
	sub := loadKey(t, "subkey.secret.asc")
	if len(sub.Subkeys) != 2 || sub.Subkeys[0].Capabilities() != "S" || sub.Subkeys[1].Capabilities() != "E" || sub.Primary.Capabilities() != "C" {
		t.Errorf("subkey capabilities: %s %v", sub.Primary.Capabilities(), sub.Subkeys)
	}
	if !sub.Primary.Private.Stub || sub.Subkeys[0].Private == nil || sub.Subkeys[0].Private.Stub {
		t.Errorf("stub detection: primary stub %v", sub.Primary.Private.Stub)
	}
	if !sub.Subkeys[0].Bound || !sub.Subkeys[1].Bound {
		t.Errorf("subkey bindings: %s / %s", sub.Subkeys[0].Problem, sub.Subkeys[1].Problem)
	}
	spec.Verified(t, reqkey.RKeyUseGnupgKeys)
}

// A protected key needs the correct passphrase.
func TestUnlocksProtectedKey(t *testing.T) {
	e := loadKey(t, "protected.secret.asc")
	if _, err := e.SigningKey(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.Unlock(nil); err == nil || !strings.Contains(err.Error(), "none was given") {
		t.Errorf("no passphrase: %v", err)
	}
	if err := e.Unlock([]byte("wrong")); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Errorf("wrong passphrase: %v", err)
	}
	var sig bytes.Buffer
	if err := SignDetached(&sig, []byte("data"), []*Entity{e}, time.Now()); err == nil {
		t.Error("signed with a locked key")
	}
	if err := e.Unlock(testdata(t, "protected.passphrase")); err != nil {
		t.Fatal(err)
	}
	if err := SignDetached(&sig, []byte("data"), []*Entity{e}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyring(e).VerifyDetached([]byte("data"), sig.Bytes()); err != nil {
		t.Fatal(err)
	}
	spec.Verified(t, reqkey.RKeyUseGnupgKeys)
}

// Without a secret primary key the signing subkey signs; the encryption key
// is never chosen.
func TestPicksSigningSubkey(t *testing.T) {
	e := loadKey(t, "subkey.secret.asc")
	k, err := e.SigningKey(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if k != e.Subkeys[0] {
		t.Fatalf("signing key %s", k.Public.Fingerprint)
	}
	var sig bytes.Buffer
	if err := SignDetached(&sig, []byte("data"), []*Entity{e}, time.Now()); err != nil {
		t.Fatal(err)
	}
	infos, err := NewKeyring(loadKey(t, "subkey.public.asc")).VerifyDetached([]byte("data"), sig.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if infos[0].Signer != e.Fingerprint() || infos[0].Key != e.Subkeys[0].Public.Fingerprint {
		t.Errorf("infos = %+v", infos)
	}
	if _, err := loadKey(t, "expired.secret.asc").SigningKey(time.Now()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expired key: %v", err)
	}
	spec.Verified(t, reqkey.RKeyUseGnupgKeys)
}

// Signatures from gpg are verified: detached and cleartext, with Ed25519,
// RSA and a subkey; SHA-1 and unknown keys are rejected.
func TestVerifiesGnuPGSignatures(t *testing.T) {
	release := testdata(t, "Release")
	ed, rsa, sub := loadKey(t, "ed25519.public.asc"), loadKey(t, "rsa3072.public.asc"), loadKey(t, "subkey.public.asc")
	ring := NewKeyring(ed, rsa, sub)
	for _, name := range []string{"Release.gpg.ed25519", "Release.gpg.rsa3072", "Release.gpg.subkey"} {
		if _, err := ring.VerifyDetached(release, testdata(t, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, tc := range []struct {
		name string
		n    int
	}{{"InRelease.ed25519", 1}, {"InRelease.rsa3072", 1}, {"InRelease.both", 2}} {
		text, infos, err := ring.VerifyCleartext(testdata(t, tc.name))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !bytes.Equal(text, release) {
			t.Errorf("%s: text differs from Release:\n%s", tc.name, text)
		}
		if len(infos) != tc.n || infos[0].Hash != "SHA512" {
			t.Errorf("%s: %+v", tc.name, infos)
		}
	}
	if _, err := ring.VerifyDetached(release, testdata(t, "Release.gpg.sha1")); err == nil || !strings.Contains(err.Error(), "weak") {
		t.Errorf("SHA-1 accepted: %v", err)
	}
	if _, err := NewKeyring(rsa).VerifyDetached(release, testdata(t, "Release.gpg.ed25519")); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("untrusted key accepted: %v", err)
	}
	if _, _, err := NewKeyring(rsa).VerifyCleartext(testdata(t, "InRelease.both")); err != nil {
		t.Errorf("one trusted of two signatures: %v", err)
	}
	tampered := bytes.Replace(testdata(t, "InRelease.ed25519"), []byte("amd64 arm64"), []byte("amd64 i386"), 1)
	if _, _, err := ring.VerifyCleartext(tampered); err == nil {
		t.Error("changed InRelease accepted")
	}
	if _, err := ring.VerifyDetached(append(bytes.Clone(release), '\n'), testdata(t, "Release.gpg.ed25519")); err == nil {
		t.Error("changed Release accepted")
	}
	spec.Verified(t, dec.RDecOpenpgpInProcess)
}

// Our own signatures pass our own verifier, with every key from GnuPG,
// detached and cleartext, also with lines full of dashes and trailing
// spaces.
func TestSignaturesVerifyWithOwnVerifier(t *testing.T) {
	text := []byte("Origin: test\n-dash\n--double\ntrailing   \n\nafter empty\n")
	protected := loadKey(t, "protected.secret.asc")
	if err := protected.Unlock(testdata(t, "protected.passphrase")); err != nil {
		t.Fatal(err)
	}
	for _, e := range []*Entity{loadKey(t, "ed25519.secret.asc"), loadKey(t, "rsa3072.secret.asc"), loadKey(t, "subkey.secret.asc"), protected} {
		var det, clear bytes.Buffer
		now := time.Now()
		if err := SignDetached(&det, text, []*Entity{e}, now); err != nil {
			t.Fatal(err)
		}
		if err := SignCleartext(&clear, text, []*Entity{e}, now); err != nil {
			t.Fatal(err)
		}
		ring := NewKeyring(e)
		if _, err := ring.VerifyDetached(text, det.Bytes()); err != nil {
			t.Errorf("%s detached: %v", e.Fingerprint(), err)
		}
		got, infos, err := ring.VerifyCleartext(clear.Bytes())
		if err != nil {
			t.Errorf("%s cleartext: %v", e.Fingerprint(), err)
			continue
		}
		if !bytes.Equal(got, text) || infos[0].Hash != "SHA512" {
			t.Errorf("%s: text %q", e.Fingerprint(), got)
		}
		if !strings.Contains(clear.String(), "\n- -dash\n- --double\n") {
			t.Errorf("dashes not escaped:\n%s", clear.String())
		}
	}
	spec.Verified(t, dec.RDecOpenpgpInProcess)
}

// Two signing keys produce two signatures; a keyring with only one of the
// two keys accepts the state (key rotation).
func TestSignsWithTwoKeys(t *testing.T) {
	old, next := loadKey(t, "rsa3072.secret.asc"), loadKey(t, "ed25519.secret.asc")
	text := []byte("Suite: stable\n")
	var det, clear bytes.Buffer
	if err := SignDetached(&det, text, []*Entity{old, next}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := SignCleartext(&clear, text, []*Entity{old, next}, time.Now()); err != nil {
		t.Fatal(err)
	}
	both := NewKeyring(old, next)
	if infos, err := both.VerifyDetached(text, det.Bytes()); err != nil || len(infos) != 2 {
		t.Fatalf("both: %v %v", infos, err)
	}
	if _, infos, err := both.VerifyCleartext(clear.Bytes()); err != nil || len(infos) != 2 {
		t.Fatalf("both cleartext: %v %v", infos, err)
	}
	for _, e := range []*Entity{old, next} {
		if _, _, err := NewKeyring(e).VerifyCleartext(clear.Bytes()); err != nil {
			t.Errorf("only %s: %v", e.Fingerprint(), err)
		}
	}
	spec.Verified(t, reqkey.RKeyRotation)
}

// A generated key signs, can be exported as secret key with and without
// passphrase and read again, and its public part verifies the signatures.
func TestGeneratedKeySignsAndVerifies(t *testing.T) {
	created := time.Now().Add(-time.Minute)
	e, err := Generate("Example APT <apt@example.com>", created, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if e.Primary.Public.Algo != algoEdDSALegacy || e.Primary.Capabilities() != "CS" || e.Primary.Expires.IsZero() {
		t.Errorf("generated key: %s %s %v", e.Primary.Public.AlgoName(), e.Primary.Capabilities(), e.Primary.Expires)
	}
	for _, pass := range [][]byte{nil, []byte("secret words")} {
		armored, err := ExportSecretArmored(e, pass)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(armored, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
			t.Errorf("armor: %.40s", armored)
		}
		es, err := ReadKeys(bytes.NewReader(armored))
		if err != nil {
			t.Fatal(err)
		}
		back := es[0]
		if back.Fingerprint() != e.Fingerprint() || back.Primary.Private.Protected() != (pass != nil) {
			t.Fatalf("re-read: %s protected=%v", back.Fingerprint(), back.Primary.Private.Protected())
		}
		if pass != nil && back.Primary.Private.s2k.hash != hashSHA256 {
			t.Errorf("S2K hash %d", back.Primary.Private.s2k.hash)
		}
		if err := back.Unlock(pass); err != nil {
			t.Fatal(err)
		}
		var sig bytes.Buffer
		if err := SignCleartext(&sig, []byte("text\n"), []*Entity{back}, time.Now()); err != nil {
			t.Fatal(err)
		}
		for _, public := range [][]byte{Export(e), ExportArmored(e)} {
			pub, err := ReadKeys(bytes.NewReader(public))
			if err != nil {
				t.Fatal(err)
			}
			if pub[0].HasSecret() {
				t.Error("public export carries a secret")
			}
			if _, _, err := NewKeyring(pub...).VerifyCleartext(sig.Bytes()); err != nil {
				t.Errorf("verify with exported key: %v", err)
			}
		}
	}
	spec.Verified(t, reqkey.RKeyGenerate)
}

// The public export of a key from GnuPG carries the same keys, user IDs and
// bindings as gpg --export, in binary and in an ASCII armor.
func TestExportBinaryAndArmored(t *testing.T) {
	secret := loadKey(t, "subkey.secret.asc")
	gpgPublic := loadKey(t, "subkey.public.asc")
	for _, data := range [][]byte{Export(secret), ExportArmored(secret)} {
		es, err := ReadKeys(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		got := es[0]
		if got.HasSecret() || got.Fingerprint() != gpgPublic.Fingerprint() || len(got.Subkeys) != len(gpgPublic.Subkeys) {
			t.Fatalf("export differs: %s %d", got.Fingerprint(), len(got.Subkeys))
		}
		for i, k := range got.Keys() {
			want := gpgPublic.Keys()[i]
			if k.Public.Fingerprint != want.Public.Fingerprint || k.Capabilities() != want.Capabilities() || !k.Bound {
				t.Errorf("key %d: %s %s bound=%v", i, k.Public.Fingerprint, k.Capabilities(), k.Bound)
			}
		}
	}
	if !bytes.Equal(Export(loadKey(t, "ed25519.public.gpg")), Export(loadKey(t, "ed25519.secret.asc"))) {
		t.Error("export of the public and of the secret key differ")
	}
	spec.Verified(t, reqkey.RKeyExportAndShow)
}
