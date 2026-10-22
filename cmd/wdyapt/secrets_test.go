package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

const testPassphrase = "correct horse battery staple 42"

// Passphrases appear in no output, no error, no JSON output and not in the
// lock file.
func TestSecretsNeverPrinted(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"WDYAPT_SIGNING_KEY_PASSPHRASE": testPassphrase}
	var all strings.Builder
	record := func(r result) result {
		all.WriteString(r.stdout)
		all.WriteString(r.stderr)
		return r
	}
	if r := record(wdyapt(t, env, "key", "generate", "--user-id", "S <s@example.com>", "--out", filepath.Join(dir, "k"), "--json", "--verbose")); r.code != 0 {
		t.Fatal(r.stderr)
	}
	writeFile(t, filepath.Join(dir, "f"), "x", 0o644)
	if r := record(wdyapt(t, map[string]string{"WDYAPT_MAINTAINER": "S <s@example.com>"}, "deb", "build", "--name", "sx", "--version", "1", "--arch", "all",
		"--summary", "s", "--file", filepath.Join(dir, "f")+":/usr/share/s/f", "--epoch", "1", "--out", dir)); r.code != 0 {
		t.Fatal(r.stderr)
	}
	pub := map[string]string{
		"WDYAPT_SIGNING_KEY_PASSPHRASE": testPassphrase,
		"WDYAPT_SIGNING_KEY":            filepath.Join(dir, "k.secret.asc"),
		"WDYAPT_REMOTE":                 filepath.Join(dir, "repo"),
		"WDYAPT_SUITE":                  "stable",
	}
	deb := filepath.Join(dir, "sx_1_all.deb")
	if r := record(wdyapt(t, pub, "publish", "--create", "--architectures", "amd64", "--verbose", "--json", deb)); r.code != 0 {
		t.Fatal(r.stderr)
	}
	wrong := map[string]string{}
	for k, v := range pub {
		wrong[k] = v
	}
	wrong["WDYAPT_SIGNING_KEY_PASSPHRASE"] = "not " + testPassphrase
	if r := record(wdyapt(t, wrong, "publish", "--verbose", deb)); r.code == 0 || !strings.Contains(r.stderr, "wrong passphrase") {
		t.Errorf("wrong passphrase: %d %s", r.code, r.stderr)
	}
	if strings.Contains(all.String(), testPassphrase) {
		t.Error("the passphrase appears in an output")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "repo", "*"))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), testPassphrase) {
			t.Errorf("%s contains the passphrase", f)
		}
	}
	spec.Verified(t, nfr.RNfrConfidentialCredentials)
}
