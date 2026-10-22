package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/sftp/sftptest"
	"github.com/worldiety/wdyapt/internal/ssh"
	"github.com/worldiety/wdyapt/internal/ssh/knownhosts"
	"github.com/worldiety/wdyapt/internal/ssh/sshtest"
	"github.com/worldiety/wdyapt/requirements/dec"
	reqaccess "github.com/worldiety/wdyapt/requirements/fun/access"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

const sftpPassword = `s3cr3t "pass" $word;|&`

// sftpServer starts SSH with password login and an SFTP subsystem on a
// directory; known_hosts knows its keys.
func sftpServer(t *testing.T, opts sftptest.Options) (*sshtest.Server, *sftptest.Server, string) {
	t.Helper()
	files, err := sftptest.New(t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := sshtest.Start(t, sshtest.Options{
		Auth: &ssh.ServerAuth{Password: func(user string, pw []byte) bool { return user == "deploy" && string(pw) == sftpPassword }},
		Subsystems: map[string]func(*ssh.Channel){"sftp": func(ch *ssh.Channel) {
			files.Serve(ch)
		}},
	})
	var kh bytes.Buffer
	for _, k := range srv.Opts.Config.HostKeys {
		kh.WriteString(knownhosts.FormatLine(srv.Addr, k.PublicKey()) + "\n")
	}
	name := filepath.Join(t.TempDir(), "known_hosts")
	writeFile(t, name, kh.String(), 0o644)
	return srv, files, name
}

func sftpEnv(env map[string]string, addr, knownHosts string) map[string]string {
	out := map[string]string{}
	for k, v := range env {
		out[k] = v
	}
	out["WDYAPT_REMOTE"] = "sftp://deploy@" + addr + "/~/debian-repository"
	out["WDYAPT_SFTP_PASSWORD"] = sftpPassword
	out["WDYAPT_KNOWN_HOSTS"] = knownHosts
	return out
}

// Publishing over SFTP end to end: create, publish again, list, verify; the
// state on the server is correct.
func TestPublishOverSFTP(t *testing.T) {
	dir, env := pipeline(t)
	srv, files, kh := sftpServer(t, sftptest.Options{})
	env = sftpEnv(env, srv.Addr, kh)
	r := wdyapt(t, env, "publish", "--create", "--verbose", filepath.Join(dir, "build"))
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"Connecting to sftp://deploy@", "matches " + kh + " line", "Logged in as deploy with password", "Uploading pool/main/t/tool/tool_1.0_amd64.deb", "Switched dists/stable/InRelease", "SFTP version 3"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
	root := filepath.Join(files.Root, "home/user/debian-repository")
	for _, f := range []string{"pool/main/t/tool/tool_1.0_amd64.deb", "dists/stable/InRelease", "dists/stable/main/binary-amd64/Packages.gz"} {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Error(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".wdyapt.lock")); err == nil {
		t.Error("lock left")
	}
	ops := strings.Join(files.Operations(), "\n")
	if !strings.Contains(ops, "posix-rename /home/user/debian-repository/dists/stable/InRelease.wdyapt-") {
		t.Errorf("no atomic rename:\n%s", ops)
	}
	if again := wdyapt(t, env, "publish", filepath.Join(dir, "build")); again.code != 0 || !strings.Contains(again.stderr, "Nothing to add") {
		t.Errorf("republish: %d %s", again.code, again.stderr)
	}
	list := wdyapt(t, env, "repo", "list", "--trusted-key", filepath.Join(dir, "key.asc"))
	if list.code != 0 || !strings.Contains(list.stdout, "tool     1.0      amd64") {
		t.Errorf("repo list over sftp: %d %s %s", list.code, list.stdout, list.stderr)
	}
	verify := wdyapt(t, env, "repo", "verify", "--check-pool", "--trusted-key", filepath.Join(dir, "key.gpg"))
	if verify.code != 0 {
		t.Errorf("repo verify over sftp: %d %s %s", verify.code, verify.stdout, verify.stderr)
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// An upload that breaks off midway leaves no half file under the final
// name; the next run succeeds.
func TestAbortedSFTPUpload(t *testing.T) {
	dir, env := pipeline(t)
	srv, files, kh := sftpServer(t, sftptest.Options{FailWriteAfter: 100})
	env = sftpEnv(env, srv.Addr, kh)
	r := wdyapt(t, env, "publish", "--create", filepath.Join(dir, "build"))
	if r.code == 0 {
		t.Fatal("upload did not fail")
	}
	root := filepath.Join(files.Root, "home/user/debian-repository")
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".deb") {
			t.Errorf("half a package under its final name: %s", p)
		}
		return nil
	})
	if _, err := os.Stat(filepath.Join(root, "dists/stable/InRelease")); err == nil {
		t.Error("switched despite the failure")
	}
	files.Opts.FailWriteAfter = 0
	again := wdyapt(t, env, "publish", "--create", "--break-lock", filepath.Join(dir, "build"))
	if again.code != 0 {
		t.Fatalf("second run: %d %s", again.code, again.stderr)
	}
	spec.Verified(t, dec.RDecAtomicPublishing)
}

// remote check reports host key, login, extensions, root and suites and
// changes nothing; --write-test creates a probe and removes it.
func TestRemoteCheckChangesNothing(t *testing.T) {
	dir, env := pipeline(t)
	srv, files, kh := sftpServer(t, sftptest.Options{})
	env = sftpEnv(env, srv.Addr, kh)
	before := wdyapt(t, env, "remote", "check")
	if before.code != 0 || !strings.Contains(before.stdout, "does not exist yet") {
		t.Fatalf("check before: %d %s %s", before.code, before.stdout, before.stderr)
	}
	if r := wdyapt(t, env, "publish", "--create", filepath.Join(dir, "build")); r.code != 0 {
		t.Fatal(r.stderr)
	}
	opsBefore := len(files.Operations())
	r := wdyapt(t, env, "remote", "check", "--json")
	var rep struct {
		Host          string   `json:"host_key"`
		LoginM        string   `json:"login"`
		RootP         string   `json:"root"`
		Extensions    []string `json:"sftp_extensions"`
		Suites        []string
		AtomicReplace bool `json:"atomic_replace"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || r.code != 0 {
		t.Fatalf("%v: %s %s", err, r.stdout, r.stderr)
	}
	if !strings.HasPrefix(rep.Host, "ssh-ed25519 SHA256:") || rep.LoginM != "password" || rep.RootP != "/home/user/debian-repository" ||
		!rep.AtomicReplace || len(rep.Suites) != 1 || rep.Suites[0] != "stable" {
		t.Errorf("report = %+v", rep)
	}
	if ops := files.Operations()[opsBefore:]; len(ops) != 0 {
		t.Errorf("remote check changed something: %v", ops)
	}
	w := wdyapt(t, env, "remote", "check", "--write-test")
	if w.code != 0 || !strings.Contains(w.stdout, "created and removed .wdyapt-check.wdyapt-") {
		t.Errorf("write test: %d %s %s", w.code, w.stdout, w.stderr)
	}
	spec.Verified(t, reqaccess.RAccessCheck)
}

// A wrong host key stops before the login; an unknown host points to
// remote hostkey; --host-key replaces known_hosts.
func TestHostKeyChecksOverSFTP(t *testing.T) {
	_, env := pipeline(t)
	srv, _, _ := sftpServer(t, sftptest.Options{})
	other := sshtest.HostKeys(t)
	var kh bytes.Buffer
	for _, k := range other {
		kh.WriteString(knownhosts.FormatLine(srv.Addr, k.PublicKey()) + "\n")
	}
	wrong := filepath.Join(t.TempDir(), "kh")
	writeFile(t, wrong, kh.String(), 0o644)
	r := wdyapt(t, sftpEnv(env, srv.Addr, wrong), "remote", "check")
	if r.code != 1 || !strings.Contains(r.stderr, "possible man-in-the-middle") || len(srv.Logins()) != 0 {
		t.Errorf("wrong key: %d %s logins %v", r.code, r.stderr, srv.Logins())
	}
	empty := filepath.Join(t.TempDir(), "kh")
	writeFile(t, empty, "", 0o644)
	r = wdyapt(t, sftpEnv(env, srv.Addr, empty), "remote", "check")
	if r.code != 1 || !strings.Contains(r.stderr, "wdyapt remote hostkey") {
		t.Errorf("unknown host: %d %s", r.code, r.stderr)
	}
	fp := ssh.Fingerprint(srv.Opts.Config.HostKeys[0].PublicKey())
	r = wdyapt(t, sftpEnv(env, srv.Addr, empty), "remote", "check", "--host-key", "SHA256:bogus,"+fp)
	if r.code != 0 || !strings.Contains(r.stderr, "matches --host-key") {
		t.Errorf("--host-key: %d %s", r.code, r.stderr)
	}
	spec.Verified(t, reqaccess.RAccessHostKey)
}

// The SFTP password appears in no output, not even with --verbose, --json
// and after a failed login, and not in the lock.
func TestSFTPPasswordNeverPrinted(t *testing.T) {
	dir, env := pipeline(t)
	srv, _, kh := sftpServer(t, sftptest.Options{})
	env = sftpEnv(env, srv.Addr, kh)
	var all strings.Builder
	for _, args := range [][]string{
		{"publish", "--create", "--verbose", "--json", filepath.Join(dir, "build")},
		{"remote", "check", "--verbose", "--json"},
		{"repo", "list", "--verbose"},
	} {
		r := wdyapt(t, env, args...)
		all.WriteString(r.stdout + r.stderr)
	}
	bad := sftpEnv(env, srv.Addr, kh)
	bad["WDYAPT_SFTP_PASSWORD"] = "x" + sftpPassword
	r := wdyapt(t, bad, "remote", "check", "--verbose")
	all.WriteString(r.stdout + r.stderr)
	if r.code != 1 || !strings.Contains(r.stderr, "tried password; the server allows password") {
		t.Errorf("wrong password: %d %s", r.code, r.stderr)
	}
	if strings.Contains(all.String(), sftpPassword) || strings.Contains(all.String(), "s3cr3t") {
		t.Error("the password appears in an output")
	}
	if err := wdyapt(t, sftpEnv(env, srv.Addr, kh), "publish", "--password-file", "x", filepath.Join(dir, "build")); err.code != 2 || !strings.Contains(err.stderr, "not both") {
		t.Errorf("password twice: %d %s", err.code, err.stderr)
	}
	spec.Verified(t, nfr.RNfrConfidentialCredentials)
}
