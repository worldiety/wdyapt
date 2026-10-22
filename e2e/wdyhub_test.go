//go:build e2e

package e2e

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestWdyhubLayout: a state as the wdyhub tool writes it and gpg signs it
// (internal/repo/testdata/wdyhub) lies on the storage; wdyapt adds a
// package and signs with the same key; the header fields stay, and apt
// sees old and new packages.
func TestWdyhubLayout(t *testing.T) {
	dir := t.TempDir()
	home := user(t, "wdyhub", password)
	fixture := filepath.Join("..", "internal", "repo", "testdata", "wdyhub")
	sh(t, "cp", "-R", filepath.Join(fixture, "repo"), filepath.Join(home, "debian-repository"))
	sh(t, "chown", "-R", "wdyhub:wdyhub", filepath.Join(home, "debian-repository"))
	before := readFile(t, filepath.Join(home, "debian-repository/dists/stable/Release"))

	s := startSSHD(t, hostKeys)
	env := map[string]string{
		"WDYAPT_REMOTE":        s.remote("wdyhub", "debian-repository"),
		"WDYAPT_SFTP_PASSWORD": password,
		"WDYAPT_KNOWN_HOSTS":   knownHosts(t, s),
		"WDYAPT_SIGNING_KEY":   filepath.Join(fixture, "key", "secret.asc"),
	}
	must(t, env, "publish", "--suite", "stable", buildPackage(t, dir, "e2e-extra", "1.0", "all"))

	after := readFile(t, filepath.Join(home, "debian-repository/dists/stable/Release"))
	head := func(r string) string {
		var keep []string
		for _, l := range strings.Split(r, "\n") {
			if l == "MD5Sum:" {
				break
			}
			if !strings.HasPrefix(l, "Date:") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	if head(before) != head(after) {
		t.Errorf("the Release header changed:\n%s\n---\n%s", head(before), head(after))
	}
	url := serve(t, filepath.Join(home, "debian-repository"))
	aptSource(t, url, "stable", filepath.Join(fixture, "key", "public.asc"))
	aptUpdate(t)
	for pkg, version := range map[string]string{"wdyhub-runner": "1.4.0", "e2e-extra": "1.0"} {
		out, _ := exec.Command("apt-cache", "policy", pkg).CombinedOutput()
		if !strings.Contains(string(out), "Candidate: "+version) {
			t.Errorf("apt does not see %s %s:\n%s", pkg, version, out)
		}
	}
	aptGet(t, "install", "e2e-extra")
	if out := sh(t, "e2e-extra"); out != "e2e-extra 1.0\n" {
		t.Errorf("installed: %q", out)
	}
	aptGet(t, "purge", "e2e-extra")
	must(t, env, "repo", "verify", "--check-pool", "--trusted-key", filepath.Join(fixture, "key", "public.asc"))
}
