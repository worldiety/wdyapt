//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// password is full of characters that a shell would misread.
const password = `p@ss w0rd!"$'\;&|*?<>(){}`

// TestPublishAndInstall: remote hostkey returns the same keys as
// ssh-keyscan; publish creates a suite using a password, an HTTP server
// serves it, apt installs with Signed-By; the second version comes with a
// key file, the third via ssh-agent, the fourth via keyboard-interactive;
// apt upgrades; a package for all is in every list.
func TestPublishAndInstall(t *testing.T) {
	dir := t.TempDir()
	home := user(t, "deployer", password)
	s := startSSHD(t, hostKeys)
	kh := knownHosts(t, s)

	// remote hostkey and ssh-keyscan see the same keys.
	ours := strings.Split(strings.TrimSpace(readFile(t, kh)), "\n")
	scan, _ := exec.Command("ssh-keyscan", "-p", strings.TrimPrefix(s.addr(), "127.0.0.1:"), "127.0.0.1").Output()
	var theirs []string
	for _, l := range strings.Split(strings.TrimSpace(string(scan)), "\n") {
		if !strings.HasPrefix(l, "#") && l != "" {
			theirs = append(theirs, l)
		}
	}
	slices.Sort(ours)
	slices.Sort(theirs)
	if !slices.Equal(ours, theirs) {
		t.Fatalf("remote hostkey:\n%s\nssh-keyscan:\n%s", strings.Join(ours, "\n"), strings.Join(theirs, "\n"))
	}

	must(t, nil, "key", "generate", "--user-id", "E2E APT <apt@example.com>", "--out", filepath.Join(dir, "apt"), "--quiet")
	a := arch(t)
	other := "amd64"
	if a == "amd64" {
		other = "arm64"
	}
	env := map[string]string{
		"WDYAPT_REMOTE":        s.remote("deployer", "repo"),
		"WDYAPT_SUITE":         "stable",
		"WDYAPT_SIGNING_KEY":   filepath.Join(dir, "apt.secret.asc"),
		"WDYAPT_KNOWN_HOSTS":   kh,
		"WDYAPT_SFTP_PASSWORD": password,
	}
	tool1 := buildPackage(t, dir, "e2e-tool", "1.0", a)
	docs := buildPackage(t, dir, "e2e-docs", "1.0", "all")
	r := must(t, env, "publish", "--create", "--architectures", a+","+other, "--origin", "E2E", "--label", "E2E Repo", tool1, docs)
	if !strings.Contains(r.stderr, "Logged in as deployer with password") {
		t.Errorf("login: %s", r.stderr)
	}

	url := serve(t, filepath.Join(home, "repo"))
	aptSource(t, url, "stable", filepath.Join(dir, "apt.gpg"))
	aptUpdate(t)
	aptGet(t, "install", "e2e-tool", "e2e-docs")
	if out := sh(t, "e2e-tool"); out != "e2e-tool 1.0\n" {
		t.Fatalf("installed: %q", out)
	}
	for _, ar := range []string{a, other} {
		resp, err := http.Get(url + "dists/stable/main/binary-" + ar + "/Packages")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "Package: e2e-docs\n") {
			t.Errorf("the all package is missing in the %s list", ar)
		}
	}

	// Version 2 with a key file, without a password.
	sh(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "id"))
	authorize(t, "deployer", filepath.Join(dir, "id.pub"))
	keyEnv := map[string]string{}
	for k, v := range env {
		if k != "WDYAPT_SFTP_PASSWORD" {
			keyEnv[k] = v
		}
	}
	keyEnv["WDYAPT_IDENTITY"] = filepath.Join(dir, "id")
	os.Chmod(filepath.Join(dir, "id"), 0o600)
	r = must(t, keyEnv, "publish", buildPackage(t, dir, "e2e-tool", "2.0", a))
	if !strings.Contains(r.stderr, "with publickey (identity file") {
		t.Errorf("login with key file: %s", r.stderr)
	}

	// Version 3 via ssh-agent.
	sock := filepath.Join(dir, "agent.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer agent.Process.Kill()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		sh(t, "sleep", "0.1")
	}
	if out, err := shIn(t, "", []string{"SSH_AUTH_SOCK=" + sock}, "ssh-add", filepath.Join(dir, "id")); err != nil {
		t.Fatalf("ssh-add: %v %s", err, out)
	}
	agentEnv := map[string]string{"SSH_AUTH_SOCK": sock}
	for k, v := range env {
		if k != "WDYAPT_SFTP_PASSWORD" {
			agentEnv[k] = v
		}
	}
	r = must(t, agentEnv, "publish", buildPackage(t, dir, "e2e-tool", "3.0", a))
	if !strings.Contains(r.stderr, "with publickey (ssh-agent") {
		t.Errorf("login with agent: %s", r.stderr)
	}

	// Version 4 via keyboard-interactive: the server accepts no password.
	s2 := startSSHD(t, hostKeys, "PasswordAuthentication=no", "PubkeyAuthentication=no")
	kbdEnv := map[string]string{}
	for k, v := range env {
		kbdEnv[k] = v
	}
	kbdEnv["WDYAPT_REMOTE"] = s2.remote("deployer", "repo")
	kbdEnv["WDYAPT_KNOWN_HOSTS"] = knownHosts(t, s2)
	r = must(t, kbdEnv, "publish", buildPackage(t, dir, "e2e-tool", "4.0", a))
	if !strings.Contains(r.stderr, "with keyboard-interactive") {
		t.Errorf("login with keyboard-interactive: %s", r.stderr)
	}

	aptUpdate(t)
	up := aptGet(t, "upgrade")
	if out := sh(t, "e2e-tool"); out != "e2e-tool 4.0\n" {
		t.Fatalf("after upgrade: %q\n%s\n%s", out, up, sh(t, "apt-cache", "policy", "e2e-tool"))
	}
	list := must(t, env, "repo", "list", "--trusted-key", filepath.Join(dir, "apt.asc"), "--package", "e2e-tool")
	if strings.Count(list.stdout, "\ne2e-tool ") != 4 {
		t.Errorf("all versions are kept:\n%s", list.stdout)
	}
	must(t, env, "repo", "verify", "--check-pool", "--trusted-key", filepath.Join(dir, "apt.gpg"))
	aptGet(t, "purge", "e2e-tool", "e2e-docs")
}
