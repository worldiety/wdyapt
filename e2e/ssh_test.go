//go:build e2e

package e2e

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// supported returns what sshd knows for query (kex, cipher, mac, key-sig).
func supported(t *testing.T, query string) map[string]bool {
	t.Helper()
	out, err := exec.Command("ssh", "-Q", query).Output()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, l := range strings.Fields(string(out)) {
		m[l] = true
	}
	return m
}

// TestAlgorithmMatrix: sshd is limited to one algorithm at a time;
// remote check succeeds with every one that wdyapt offers and sshd knows.
// mlkem768x25519-sha256 exists only from OpenSSH 10 (Ubuntu 26.04).
func TestAlgorithmMatrix(t *testing.T) {
	user(t, "matrix", password)
	type c struct {
		opts []string
		want string
	}
	var cases []c
	kex := supported(t, "kex")
	for _, k := range []string{"mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256"} {
		if !kex[k] {
			if k == "mlkem768x25519-sha256" && ubuntu() == "26.04" {
				t.Errorf("OpenSSH on Ubuntu 26.04 lacks %s", k)
			}
			t.Logf("sshd does not know %s", k)
			continue
		}
		cases = append(cases, c{[]string{"KexAlgorithms=" + k}, "kex " + k + ","})
	}
	for _, ci := range []string{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"} {
		cases = append(cases, c{[]string{"Ciphers=" + ci}, "cipher " + ci})
	}
	for _, m := range []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"} {
		cases = append(cases, c{[]string{"Ciphers=aes128-ctr", "MACs=" + m}, "cipher aes128-ctr " + m})
	}
	for _, h := range []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"} {
		cases = append(cases, c{[]string{"HostKeyAlgorithms=" + h}, "host key " + h + ","})
	}
	for _, tc := range cases {
		s := startSSHD(t, hostKeys, tc.opts...)
		kh := knownHosts(t, s)
		r := wdyapt(t, map[string]string{"WDYAPT_SFTP_PASSWORD": password}, "remote", "check", "--remote", s.remote("matrix", "repo"), "--known-hosts", kh)
		if r.code != 0 || !strings.Contains(r.stdout, tc.want) || !strings.Contains(r.stdout, "strict kex") {
			t.Errorf("%v: exit %d, want %q\n%s%s\nsshd:\n%s", tc.opts, r.code, tc.want, r.stdout, r.stderr, s.log.String())
		}
	}
}

// TestRekeyDuringUpload: sshd exchanges new keys after every MiB; a
// package of 50 MB arrives unchanged.
func TestRekeyDuringUpload(t *testing.T) {
	dir := t.TempDir()
	home := user(t, "rekey", password)
	s := startSSHD(t, hostKeys, "RekeyLimit=1M")
	big := filepath.Join(dir, "big")
	data := make([]byte, 50<<20)
	rand.Read(data)
	if err := os.WriteFile(big, data, 0o644); err != nil {
		t.Fatal(err)
	}
	r := must(t, nil, "deb", "build", "--name", "e2e-big", "--version", "1", "--arch", "all", "--maintainer", "E2E <e2e@example.com>",
		"--summary", "big", "--file", big+":/usr/share/e2e-big/big", "--epoch", "1", "--out", dir, "--quiet")
	deb := strings.TrimSpace(r.stdout)
	must(t, nil, "key", "generate", "--user-id", "R <r@example.com>", "--out", filepath.Join(dir, "k"), "--quiet")
	env := map[string]string{"WDYAPT_SFTP_PASSWORD": password}
	must(t, env, "publish", "--remote", s.remote("rekey", "repo"), "--known-hosts", knownHosts(t, s), "--suite", "stable", "--create",
		"--architectures", "amd64", "--signing-key", filepath.Join(dir, "k.secret.asc"), deb)
	got := sha256File(t, filepath.Join(home, "repo/pool/main/e/e2e-big/e2e-big_1_all.deb"))
	if want := sha256File(t, deb); got != want {
		t.Fatalf("SHA256 on the server %s, want %s", got, want)
	}
	if n := strings.Count(s.log.String(), "rekey"); n == 0 {
		t.Logf("sshd log does not mention rekeying:\n%s", s.log.String())
	}
}

// TestTamperingAndRefusals: a changed list stops before the upload; a
// wrong host key stops before the login; a foreign signing key is
// rejected; a held lock gives exit 75.
func TestTamperingAndRefusals(t *testing.T) {
	dir := t.TempDir()
	home := user(t, "tamper", password)
	s := startSSHD(t, hostKeys)
	kh := knownHosts(t, s)
	must(t, nil, "key", "generate", "--user-id", "T <t@example.com>", "--out", filepath.Join(dir, "k"), "--quiet")
	must(t, nil, "key", "generate", "--user-id", "Other <o@example.com>", "--out", filepath.Join(dir, "other"), "--quiet")
	env := map[string]string{
		"WDYAPT_SFTP_PASSWORD": password, "WDYAPT_REMOTE": s.remote("tamper", "repo"), "WDYAPT_KNOWN_HOSTS": kh,
		"WDYAPT_SUITE": "stable", "WDYAPT_SIGNING_KEY": filepath.Join(dir, "k.secret.asc"),
	}
	must(t, env, "publish", "--create", "--architectures", "amd64", buildPackage(t, dir, "e2e-a", "1", "all"))

	list := filepath.Join(home, "repo/dists/stable/main/binary-amd64/Packages")
	orig := readFile(t, list)
	writeFile(t, list, strings.Replace(orig, "Package: e2e-a", "Package: e2e-evil", 1), 0o644)
	r := wdyapt(t, env, "publish", buildPackage(t, dir, "e2e-b", "1", "all"))
	if r.code != 1 || !strings.Contains(r.stderr, "someone changed the repository") {
		t.Errorf("tampered list: %d %s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(home, "repo/pool/main/e/e2e-b")); err == nil {
		t.Error("uploaded after a failed check")
	}
	writeFile(t, list, orig, 0o644)

	wrong := startSSHD(t, otherKeys)
	before := strings.Count(wrong.log.String(), "Accepted")
	r = wdyapt(t, map[string]string{"WDYAPT_SFTP_PASSWORD": password}, "remote", "check", "--remote", fmt.Sprintf("sftp://tamper@%s/~/repo", wrong.addr()),
		"--known-hosts", kh)
	if r.code != 1 || !strings.Contains(r.stderr, "not in the known_hosts file") {
		t.Errorf("unknown host: %d %s", r.code, r.stderr)
	}
	// Same address, other keys: known_hosts names those of s.
	moved := filepath.Join(dir, "kh-moved")
	writeFile(t, moved, strings.ReplaceAll(readFile(t, kh), s.addr()[len("127.0.0.1:"):], wrong.addr()[len("127.0.0.1:"):]), 0o644)
	r = wdyapt(t, map[string]string{"WDYAPT_SFTP_PASSWORD": password}, "remote", "check", "--remote", fmt.Sprintf("sftp://tamper@%s/~/repo", wrong.addr()), "--known-hosts", moved)
	if r.code != 1 || !strings.Contains(r.stderr, "possible man-in-the-middle") {
		t.Errorf("changed host key: %d %s", r.code, r.stderr)
	}
	if strings.Count(wrong.log.String(), "Accepted") != before || strings.Contains(wrong.log.String(), "Failed password") {
		t.Errorf("tried to log in despite the host key:\n%s", wrong.log.String())
	}

	foreign := map[string]string{}
	for k, v := range env {
		foreign[k] = v
	}
	foreign["WDYAPT_SIGNING_KEY"] = filepath.Join(dir, "other.secret.asc")
	if r := wdyapt(t, foreign, "publish", buildPackage(t, dir, "e2e-c", "1", "all")); r.code != 1 || !strings.Contains(r.stderr, "not trusted") {
		t.Errorf("foreign key: %d %s", r.code, r.stderr)
	}

	writeFile(t, filepath.Join(home, "repo/.wdyapt.lock"), `{"host":"ci","user":"runner","pid":1}`, 0o644)
	if r := wdyapt(t, env, "publish", buildPackage(t, dir, "e2e-d", "1", "all")); r.code != 75 {
		t.Errorf("held lock: %d %s", r.code, r.stderr)
	}
}
