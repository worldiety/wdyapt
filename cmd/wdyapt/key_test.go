package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/openpgp"
	reqkey "github.com/worldiety/wdyapt/requirements/fun/key"
)

const gnupgData = "../../internal/openpgp/testdata/"

// key generate writes three files, the secret key with 0600 and never over
// an existing file, and names the fingerprint.
func TestKeyGenerate(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "keys", "apt")
	pass := filepath.Join(dir, "pass")
	writeFile(t, pass, "s3cret words\n", 0o600)
	r := wdyapt(t, nil, "key", "generate", "--user-id", "Example APT <apt@example.com>", "--out", prefix, "--passphrase-file", pass, "--expires", "8760h")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	fp := strings.TrimSpace(r.stdout)
	if len(fp) != 40 {
		t.Fatalf("stdout = %q", r.stdout)
	}
	info, err := os.Stat(prefix + ".secret.asc")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secret key file: %v %v", info, err)
	}
	es, err := readKeyFile(prefix + ".secret.asc")
	if err != nil {
		t.Fatal(err)
	}
	if !es[0].Primary.Private.Protected() || es[0].Fingerprint().String() != fp {
		t.Errorf("secret key: protected=%v", es[0].Primary.Private.Protected())
	}
	if err := es[0].Unlock([]byte("s3cret words")); err != nil {
		t.Errorf("unlock with the passphrase from the file: %v", err)
	}
	for _, name := range []string{prefix + ".gpg", prefix + ".asc"} {
		pub, err := readKeyFile(name)
		if err != nil || pub[0].HasSecret() || pub[0].Fingerprint().String() != fp {
			t.Errorf("%s: %v", name, err)
		}
	}
	before, _ := os.ReadFile(prefix + ".secret.asc")
	again := wdyapt(t, nil, "key", "generate", "--user-id", "Other <o@example.com>", "--out", prefix)
	after, _ := os.ReadFile(prefix + ".secret.asc")
	if again.code != 1 || !strings.Contains(again.stderr, "never overwrites") || !bytes.Equal(before, after) {
		t.Errorf("second generate: %d %s", again.code, again.stderr)
	}
	spec.Verified(t, reqkey.RKeyGenerate)
}

// key show shows fingerprint, user ID, algorithm, capabilities and
// protection without needing a passphrase.
func TestShowKey(t *testing.T) {
	r := wdyapt(t, nil, "key", "show", gnupgData+"protected.secret.asc", gnupgData+"subkey.secret.asc")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{
		"6E87A2CB2FAAAE997DF807D82B3308F18AB73061", "user ID       Test Protected <protected@example.com>",
		"secret part   yes, protected by a passphrase", "capabilities  CS", "algorithm     ed25519 (EdDSA legacy)",
		"secret part   no (stub without secret part)", "    capabilities  S ", "ecdh Curve25519",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("key show lacks %q:\n%s", want, r.stdout)
		}
	}
	j := wdyapt(t, nil, "key", "show", "--json", gnupgData+"rsa3072.public.asc")
	var shown struct {
		Keys []struct {
			Primary struct{ Fingerprint, Algorithm, Secret string }
			UserIDs []string `json:"user_ids"`
		}
	}
	if err := json.Unmarshal([]byte(j.stdout), &shown); err != nil {
		t.Fatal(err)
	}
	if k := shown.Keys[0]; k.Primary.Algorithm != "rsa3072" || k.Primary.Secret != "no" || k.UserIDs[0] != "Test RSA <rsa@example.com>" {
		t.Errorf("json = %+v", shown)
	}
	spec.Verified(t, reqkey.RKeyExportAndShow)
}

// key export writes the public part in binary or as ASCII.
func TestKeyExport(t *testing.T) {
	r := wdyapt(t, map[string]string{"WDYAPT_SIGNING_KEY": gnupgData + "ed25519.secret.asc"}, "key", "export")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	want, _ := os.ReadFile(gnupgData + "ed25519.public.gpg")
	es, err := openpgp.ReadKeys(bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	if r.stdout != string(openpgp.Export(es[0])) {
		t.Error("binary export differs from the export of gpg's public key")
	}
	out := filepath.Join(t.TempDir(), "key.asc")
	r = wdyapt(t, nil, "key", "export", "--signing-key", gnupgData+"ed25519.secret.asc", "--format", "armored", "--out", out)
	data, _ := os.ReadFile(out)
	if r.code != 0 || !bytes.HasPrefix(data, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) || bytes.Contains(data, []byte("PRIVATE")) {
		t.Errorf("armored: %d %s %.60s", r.code, r.stderr, data)
	}
	spec.Verified(t, reqkey.RKeyExportAndShow)
}
