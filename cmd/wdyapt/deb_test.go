package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/cli"
	reqpkg "github.com/worldiety/wdyapt/requirements/fun/pkg"
)

// result is an invocation of wdyapt in a test.
type result struct {
	code           int
	stdout, stderr string
}

// wdyapt runs the program with args and the environment env.
func wdyapt(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	code := program().Main(context.Background(), cli.Environment{
		Args:   args,
		Stdout: &out,
		Stderr: &errOut,
		Getenv: func(k string) string { return env[k] },
	})
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
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

// deb build builds one package per architecture from options, writes the
// paths to Stdout, and deb info shows them again.
func TestBuildFromFlags(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bin", "hello-amd64.sh"), "#!/bin/sh\necho amd64\n", 0o755)
	writeFile(t, filepath.Join(dir, "bin", "hello-arm64.sh"), "#!/bin/sh\necho arm64\n", 0o755)
	writeFile(t, filepath.Join(dir, "hello.conf"), "x=1\n", 0o644)
	writeFile(t, filepath.Join(dir, "postinst"), "#!/bin/sh\n", 0o755)
	out := filepath.Join(dir, "out")
	args := []string{"deb", "build", "--name", "hello", "--version", "1.0-1", "--arch", "amd64,arm64",
		"--summary", "Says hello", "--depends", "libc6, adduser",
		"--file", filepath.Join(dir, "bin", "hello-{arch}.sh") + ":/usr/bin/hello:0755",
		"--file", filepath.Join(dir, "hello.conf") + ":/etc/hello.conf",
		"--conffile", "/etc/hello.conf", "--symlink", "/usr/sbin/hello:/usr/bin/hello",
		"--dir", "/var/lib/hello:0750", "--postinst", filepath.Join(dir, "postinst"),
		"--field", "X-Test: yes", "--out", out}
	env := map[string]string{"WDYAPT_MAINTAINER": "A B <a@example.com>", "SOURCE_DATE_EPOCH": "1791000000"}
	r := wdyapt(t, env, args...)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	want := filepath.Join(out, "hello_1.0-1_amd64.deb") + "\n" + filepath.Join(out, "hello_1.0-1_arm64.deb") + "\n"
	if r.stdout != want {
		t.Errorf("stdout = %q, want %q", r.stdout, want)
	}
	if !strings.Contains(r.stderr, "Wrote ") {
		t.Errorf("stderr = %q", r.stderr)
	}
	again := wdyapt(t, env, args...)
	if again.code != 0 || !strings.Contains(again.stderr, "unchanged") {
		t.Errorf("second build: %d %s", again.code, again.stderr)
	}

	info := wdyapt(t, nil, "deb", "info", filepath.Join(out, "hello_1.0-1_arm64.deb"))
	if info.code != 0 {
		t.Fatalf("deb info: %s", info.stderr)
	}
	for _, w := range []string{"Package: hello\n", "Depends: libc6, adduser\n", "X-Test: yes\n", "Conffiles:\n  /etc/hello.conf\n", "Maintainer scripts: postinst\n",
		"-rwxr-xr-x", "./usr/bin/hello\n", "./usr/sbin/hello -> /usr/bin/hello", "drwxr-x---", "Pool path (component main): pool/main/h/hello/hello_1.0-1_arm64.deb"} {
		if !strings.Contains(info.stdout, w) {
			t.Errorf("deb info lacks %q:\n%s", w, info.stdout)
		}
	}
	spec.Verified(t, reqpkg.RPkgBuildFromFiles, reqpkg.RPkgShow)
}

// Missing details are reported together; no file is created.
func TestBuildReportsAllProblems(t *testing.T) {
	out := t.TempDir()
	r := wdyapt(t, nil, "deb", "build", "--name", "X", "--epoch", "0", "--out", out)
	if r.code != 1 {
		t.Fatalf("exit %d", r.code)
	}
	for _, w := range []string{"invalid package name", "the version is missing", "no architecture given", "the maintainer is missing", "the summary is missing", "no files"} {
		if !strings.Contains(r.stderr, w) {
			t.Errorf("stderr lacks %q:\n%s", w, r.stderr)
		}
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("files written: %v", entries)
	}
	spec.Verified(t, reqpkg.RPkgValidateInput)
}

// With --json, deb build describes the packages and deb info their contents.
func TestDebJSON(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "m.json")
	writeFile(t, filepath.Join(dir, "doc.txt"), "hello\n", 0o644)
	writeFile(t, manifest, `{"package": "doc", "version": "2", "architectures": ["all"], "maintainer": "A B <a@example.com>",
"summary": "Docs", "files": [{"src": "doc.txt", "dst": "/usr/share/doc/doc/doc.txt"}]}`, 0o644)
	r := wdyapt(t, nil, "deb", "build", "--manifest", manifest, "--epoch", "1", "--out", dir, "--json", "--quiet")
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var built struct {
		Packages []struct {
			Path, Architecture, SHA256 string
			Size                       int64
		}
	}
	if err := json.Unmarshal([]byte(r.stdout), &built); err != nil {
		t.Fatal(err)
	}
	if len(built.Packages) != 1 || built.Packages[0].Architecture != "all" || len(built.Packages[0].SHA256) != 64 {
		t.Fatalf("built = %+v", built)
	}
	info := wdyapt(t, nil, "deb", "info", "--json", built.Packages[0].Path)
	var shown struct {
		Packages []struct {
			Control  map[string]string
			SHA256   string
			PoolPath string `json:"pool_path"`
		}
	}
	if err := json.Unmarshal([]byte(info.stdout), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Packages[0].SHA256 != built.Packages[0].SHA256 || shown.Packages[0].Control["Package"] != "doc" || shown.Packages[0].PoolPath != "pool/main/d/doc/doc_2_all.deb" {
		t.Errorf("shown = %+v", shown)
	}
	spec.Verified(t, reqpkg.RPkgShow)
}
