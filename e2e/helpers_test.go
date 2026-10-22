//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// work is the directory for the program and the host keys of all tests.
const work = "/tmp/wdyapt-e2e"

var (
	wdyaptBin string
	hostKeys  = filepath.Join(work, "hostkeys")
	otherKeys = filepath.Join(work, "otherkeys")
)

// TestMain runs only in the testbed: the tests create users, start sshd
// and install packages.
func TestMain(m *testing.M) {
	if os.Getenv("WDYAPT_TESTBED") != "1" {
		fmt.Println("skipping the E2E tests: they change the machine; run them with \"just test-e2e\"")
		os.Exit(0)
	}
	os.RemoveAll(work)
	for _, dir := range []string{hostKeys, otherKeys} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			panic(err)
		}
		for _, typ := range []string{"ed25519", "ecdsa", "rsa"} {
			out, err := exec.Command("ssh-keygen", "-q", "-t", typ, "-N", "", "-f", filepath.Join(dir, "ssh_host_"+typ+"_key")).CombinedOutput()
			if err != nil {
				panic(string(out))
			}
		}
	}
	wdyaptBin = filepath.Join(work, "wdyapt")
	build := exec.Command("go", "build", "-o", wdyaptBin, "./cmd/wdyapt")
	build.Dir = ".."
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		panic(string(out))
	}
	os.Exit(m.Run())
}

// result is one invocation of wdyapt.
type result struct {
	code           int
	stdout, stderr string
}

// wdyapt runs the program with a clean environment plus env.
func wdyapt(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	cmd := exec.Command(wdyaptBin, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

// must runs wdyapt and expects success.
func must(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	r := wdyapt(t, env, args...)
	if r.code != 0 {
		t.Fatalf("wdyapt %s: exit %d\n%s%s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

// sh runs a program and expects success.
func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// shIn runs a program with input and environment.
func shIn(t *testing.T, stdin string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeFile(t *testing.T, name, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sha256File(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

// arch is the Debian architecture of the testbed.
func arch(t *testing.T) string {
	return strings.TrimSpace(sh(t, "dpkg", "--print-architecture"))
}

// ubuntu is the Ubuntu version of the testbed.
func ubuntu() string { return os.Getenv("UBUNTU") }

// user creates a user with a password and returns its home
// directory.
func user(t *testing.T, name, password string) string {
	t.Helper()
	if _, err := exec.Command("id", name).CombinedOutput(); err != nil {
		sh(t, "useradd", "-m", "-s", "/bin/bash", name)
	}
	if out, err := shIn(t, name+":"+password+"\n", nil, "chpasswd"); err != nil {
		t.Fatalf("chpasswd: %v %s", err, out)
	}
	home := "/home/" + name
	os.Chmod(home, 0o755)
	return home
}

// authorize adds a public key for name.
func authorize(t *testing.T, name, pubFile string) {
	t.Helper()
	home := "/home/" + name
	writeFile(t, home+"/.ssh/authorized_keys", readFile(t, pubFile), 0o600)
	sh(t, "chown", "-R", name+":"+name, home+"/.ssh")
	os.Chmod(home+"/.ssh", 0o700)
}

// sshd is a running OpenSSH server.
type sshd struct {
	port int
	log  *syncBuffer
}

func (s *sshd) addr() string { return "127.0.0.1:" + strconv.Itoa(s.port) }

// remote is the address of a repository in the home directory of user.
func (s *sshd) remote(user, dir string) string {
	return fmt.Sprintf("sftp://%s@%s/~/%s", user, s.addr(), dir)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// opensshMajor returns the major version of sshd.
func opensshMajor(t *testing.T) float64 {
	out, _ := exec.Command("ssh", "-V").CombinedOutput()
	m := regexp.MustCompile(`OpenSSH_(\d+\.\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("ssh -V: %s", out)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

// startSSHD starts sshd on a free port with the host keys in keys and
// further options opts (each "Name=Value").
func startSSHD(t *testing.T, keys string, opts ...string) *sshd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := []string{
		"Port " + strconv.Itoa(port),
		"ListenAddress 127.0.0.1",
		"HostKey " + keys + "/ssh_host_ed25519_key",
		"HostKey " + keys + "/ssh_host_ecdsa_key",
		"HostKey " + keys + "/ssh_host_rsa_key",
		"PasswordAuthentication yes",
		"KbdInteractiveAuthentication yes",
		"PubkeyAuthentication yes",
		"UsePAM yes",
		"Subsystem sftp internal-sftp",
		"PidFile none",
		"StrictModes no",
		"LogLevel VERBOSE",
	}
	if opensshMajor(t) >= 9.8 {
		// OpenSSH 10 penalizes many quick connections; the tests do exactly
		// that.
		cfg = append(cfg, "PerSourcePenalties no")
	}
	name := filepath.Join(t.TempDir(), "sshd_config")
	writeFile(t, name, strings.Join(cfg, "\n")+"\n", 0o600)
	args := []string{"-D", "-e", "-f", name}
	for _, o := range opts {
		args = append(args, "-o", o)
	}
	cmd := exec.Command("/usr/sbin/sshd", args...)
	log := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			c.Close()
			return &sshd{port: port, log: log}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sshd did not start:\n%s", log.String())
	return nil
}

// knownHosts writes the known_hosts lines of s as remote hostkey fetches
// them.
func knownHosts(t *testing.T, s *sshd) string {
	t.Helper()
	r := must(t, nil, "remote", "hostkey", s.addr())
	name := filepath.Join(t.TempDir(), "known_hosts")
	writeFile(t, name, r.stdout, 0o644)
	return name
}

// serve serves dir over HTTP and returns the address.
func serve(t *testing.T, dir string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	files := http.FileServer(http.Dir(dir))
	// No conditional requests: several runs within one second would
	// otherwise have the same time, and the server would answer 304.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("If-Modified-Since")
		r.Header.Del("If-None-Match")
		files.ServeHTTP(w, r)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String() + "/"
}

// aptSource adds a repository with Signed-By. The key goes to
// /etc/apt/keyrings, where the user _apt can read it.
func aptSource(t *testing.T, url, suite, key string) {
	t.Helper()
	keyring := "/etc/apt/keyrings/wdyapt-e2e" + filepath.Ext(key)
	writeFile(t, keyring, readFile(t, key), 0o644)
	name := "/etc/apt/sources.list.d/wdyapt-e2e.sources"
	writeFile(t, name, fmt.Sprintf("Types: deb\nURIs: %s\nSuites: %s\nComponents: main\nSigned-By: %s\n", url, suite, keyring), 0o644)
	t.Cleanup(func() {
		os.Remove(name)
		os.Remove(keyring)
		exec.Command("apt-get", "update", "-qq").Run()
	})
}

// aptUpdate reads the repositories; every warning is an error.
func aptUpdate(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("apt-get", "update", "-o", "APT::Update::Error-Mode=any").CombinedOutput()
	if err != nil || regexp.MustCompile(`(?m)^(W|E|Err):`).Match(out) {
		t.Fatalf("apt-get update: %v\n%s", err, out)
	}
	return string(out)
}

// aptGet runs apt-get without prompts.
func aptGet(t *testing.T, args ...string) string {
	t.Helper()
	out, err := shIn(t, "", []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", append([]string{"-y", "-q"}, args...)...)
	if err != nil {
		t.Fatalf("apt-get %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// buildPackage builds a package with a script /usr/bin/NAME that prints
// VERSION.
func buildPackage(t *testing.T, dir, name, version, arch string, extra ...string) string {
	t.Helper()
	src := filepath.Join(dir, "src-"+name+"-"+version)
	writeFile(t, src, "#!/bin/sh\necho "+name+" "+version+"\n", 0o755)
	args := []string{"deb", "build", "--name", name, "--version", version, "--arch", arch,
		"--maintainer", "E2E <e2e@example.com>", "--summary", "E2E package " + name,
		"--file", src + ":/usr/bin/" + name + ":0755", "--epoch", "1791000000", "--out", filepath.Join(dir, "build-"+version), "--quiet"}
	r := must(t, nil, append(args, extra...)...)
	return strings.TrimSpace(r.stdout)
}
