//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gpg runs gpg with its own GNUPGHOME and without prompts.
func gpg(t *testing.T, home, pass string, args ...string) string {
	t.Helper()
	base := []string{"--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", pass}
	out, err := shIn(t, "", []string{"GNUPGHOME=" + home}, "gpg", append(base, args...)...)
	if err != nil {
		t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func fingerprint(t *testing.T, home, uid string) string {
	t.Helper()
	out, _ := shIn(t, "", []string{"GNUPGHOME=" + home}, "gpg", "--with-colons", "--list-keys", uid)
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "fpr:") {
			return strings.Split(l, ":")[9]
		}
	}
	t.Fatalf("no fingerprint for %s", uid)
	return ""
}

// gpgvAccepts checks Release.gpg and InRelease of a suite with gpgv and sqv.
func gpgvAccepts(t *testing.T, dist, keyring string) {
	t.Helper()
	for _, args := range [][]string{
		{"--keyring", keyring, dist + "/Release.gpg", dist + "/Release"},
		{"--keyring", keyring, dist + "/InRelease"},
	} {
		if out, err := exec.Command("gpgv", args...).CombinedOutput(); err != nil || !strings.Contains(string(out), "Good signature") {
			t.Errorf("gpgv %v: %v\n%s", args, err, out)
		}
	}
	if out, err := exec.Command("sqv", "--keyring", keyring, dist+"/Release.gpg", dist+"/Release").CombinedOutput(); err != nil {
		t.Errorf("sqv Release.gpg: %v\n%s", err, out)
	}
	if ubuntu() != "24.04" {
		// sqv 1.1 in Ubuntu 24.04 does not know cleartext signatures.
		out, err := exec.Command("sqv", "--keyring", keyring, "--message", "--output", filepath.Join(t.TempDir(), "text"), dist+"/InRelease").CombinedOutput()
		if err != nil {
			t.Errorf("sqv InRelease: %v\n%s", err, out)
		}
	}
}

// TestGnuPGInterop: keys from gpg (Ed25519, RSA 3072, with passphrase,
// subkeys only) sign through wdyapt, and gpgv and sqv accept the
// signatures; wdyapt verifies a state that gpg signed; gpg imports a
// wdyapt key with passphrase and signs with it.
func TestGnuPGInterop(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "gnupg")
	os.MkdirAll(home, 0o700)
	const pass = "gpg passphrase 1"
	gpg(t, home, "", "--quick-gen-key", "Ed <ed@example.com>", "ed25519", "sign", "never")
	gpg(t, home, "", "--quick-gen-key", "Rsa <rsa@example.com>", "rsa3072", "sign", "never")
	gpg(t, home, pass, "--quick-gen-key", "Prot <prot@example.com>", "ed25519", "sign", "never")
	gpg(t, home, "", "--quick-gen-key", "Sub <sub@example.com>", "ed25519", "cert", "never")
	gpg(t, home, "", "--quick-add-key", fingerprint(t, home, "sub@example.com"), "ed25519", "sign", "never")

	pkg := buildPackage(t, dir, "e2e-gpg", "1.0", "all")
	repo := filepath.Join(dir, "repo")
	for _, k := range []struct {
		uid, pass, export string
	}{
		{"ed@example.com", "", "--export-secret-keys"},
		{"rsa@example.com", "", "--export-secret-keys"},
		{"prot@example.com", pass, "--export-secret-keys"},
		{"sub@example.com", "", "--export-secret-subkeys"},
	} {
		name := strings.Split(k.uid, "@")[0]
		secret := filepath.Join(dir, name+".secret.asc")
		writeFile(t, secret, gpg(t, home, k.pass, "--armor", k.export, k.uid), 0o600)
		public := filepath.Join(dir, name+".gpg")
		writeFile(t, public, gpg(t, home, "", "--export", k.uid), 0o644)
		env := map[string]string{"WDYAPT_SIGNING_KEY_PASSPHRASE": k.pass}
		must(t, env, "publish", "--remote", repo, "--suite", name, "--create", "--architectures", "amd64",
			"--signing-key", secret, pkg)
		gpgvAccepts(t, filepath.Join(repo, "dists", name), public)
	}

	// gpg re-signs a state; wdyapt verifies it with the gpg key and
	// carries it on.
	dist := filepath.Join(repo, "dists", "ed")
	gpg(t, home, "", "--local-user", "rsa@example.com", "--digest-algo", "SHA512", "--clearsign", "--output", dist+"/InRelease", dist+"/Release")
	gpg(t, home, "", "--local-user", "rsa@example.com", "--digest-algo", "SHA512", "--armor", "--detach-sign", "--output", dist+"/Release.gpg", dist+"/Release")
	must(t, nil, "repo", "verify", "--remote", repo, "--suite", "ed", "--trusted-key", filepath.Join(dir, "rsa.gpg"))
	if r := wdyapt(t, nil, "repo", "verify", "--remote", repo, "--suite", "ed", "--trusted-key", filepath.Join(dir, "ed.gpg")); r.code != 1 {
		t.Errorf("verify with the wrong key: exit %d", r.code)
	}
	must(t, nil, "publish", "--remote", repo, "--suite", "ed", "--signing-key", filepath.Join(dir, "ed.secret.asc"),
		"--trusted-key", filepath.Join(dir, "rsa.gpg"), buildPackage(t, dir, "e2e-gpg2", "1.0", "all"))
	gpgvAccepts(t, dist, filepath.Join(dir, "ed.gpg"))

	// gpg imports a wdyapt key with passphrase.
	const wpass = "wdyapt passphrase 2"
	must(t, map[string]string{"WDYAPT_SIGNING_KEY_PASSPHRASE": wpass}, "key", "generate", "--user-id", "W <w@example.com>", "--out", filepath.Join(dir, "w"), "--quiet")
	gpg(t, home, wpass, "--import", filepath.Join(dir, "w.secret.asc"))
	writeFile(t, filepath.Join(dir, "data"), "hello\n", 0o644)
	gpg(t, home, wpass, "--local-user", "w@example.com", "--digest-algo", "SHA512", "--armor", "--detach-sign", "--output", filepath.Join(dir, "data.asc"), filepath.Join(dir, "data"))
	if out, err := exec.Command("gpgv", "--keyring", filepath.Join(dir, "w.gpg"), filepath.Join(dir, "data.asc"), filepath.Join(dir, "data")).CombinedOutput(); err != nil {
		t.Errorf("gpgv with the wdyapt key: %v\n%s", err, out)
	}
	if show := must(t, nil, "key", "show", filepath.Join(dir, "sub.secret.asc")).stdout; !strings.Contains(show, "stub without secret part") {
		t.Errorf("key show of a subkey export:\n%s", show)
	}
}
