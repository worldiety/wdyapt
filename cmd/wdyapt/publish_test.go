package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/fun/repo"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

// pipeline creates keys and a package and returns the environment with
// which a pipeline invokes wdyapt.
func pipeline(t *testing.T) (dir string, env map[string]string) {
	t.Helper()
	dir = t.TempDir()
	if r := wdyapt(t, nil, "key", "generate", "--user-id", "CI <ci@example.com>", "--out", filepath.Join(dir, "key"), "--quiet"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	writeFile(t, filepath.Join(dir, "tool"), "#!/bin/sh\n", 0o755)
	if r := wdyapt(t, map[string]string{"WDYAPT_MAINTAINER": "CI <ci@example.com>", "SOURCE_DATE_EPOCH": "1791000000"},
		"deb", "build", "--name", "tool", "--version", "1.0", "--arch", "amd64", "--summary", "A tool",
		"--file", filepath.Join(dir, "tool")+":/usr/bin/tool", "--out", filepath.Join(dir, "build"), "--quiet"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	return dir, map[string]string{
		"WDYAPT_REMOTE":      filepath.Join(dir, "repo"),
		"WDYAPT_SUITE":       "stable",
		"WDYAPT_SIGNING_KEY": filepath.Join(dir, "key.secret.asc"),
	}
}

// A pipeline sets everything via the environment; arguments override it.
func TestEnvironmentOverridesDefaults(t *testing.T) {
	dir, env := pipeline(t)
	r := wdyapt(t, env, "publish", "--create", filepath.Join(dir, "build"))
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "added tool 1.0 amd64 pool/main/t/tool/tool_1.0_amd64.deb") {
		t.Errorf("stdout = %q", r.stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "repo/dists/stable/InRelease")); err != nil {
		t.Error(err)
	}
	r = wdyapt(t, env, "publish", "--suite", "testing", "--create", filepath.Join(dir, "build"))
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "repo/dists/testing/InRelease")); err != nil {
		t.Errorf("--suite did not win over WDYAPT_SUITE: %v", err)
	}
	spec.Verified(t, nfr.RNfrHumansAndPipelines, repo.RRepoPublishPackages)
}

// Exit codes: 0 also for nothing to do, 1 for an error, 2 for wrong usage,
// 75 for a held lock.
func TestExitCodes(t *testing.T) {
	dir, env := pipeline(t)
	build := filepath.Join(dir, "build")
	for _, tc := range []struct {
		name string
		env  map[string]string
		args []string
		code int
		msg  string
	}{
		{"publish", env, []string{"publish", "--create", build}, 0, "Published 1 package"},
		{"nothing to do", env, []string{"publish", build}, 0, "Nothing to add"},
		{"no suite", map[string]string{"WDYAPT_REMOTE": env["WDYAPT_REMOTE"]}, []string{"publish", build}, 2, "--suite or WDYAPT_SUITE is required"},
		{"no packages", env, []string{"publish"}, 2, "name at least one DEB"},
		{"https", map[string]string{"WDYAPT_SUITE": "stable"}, []string{"publish", "--remote", "https://example.com/repo", build}, 2, "read-only"},
		{"missing suite", env, []string{"publish", "--suite", "stabel", build}, 1, "--create"},
		{"verify without keys", env, []string{"repo", "verify"}, 2, "--trusted-key"},
	} {
		r := wdyapt(t, tc.env, tc.args...)
		if r.code != tc.code || !strings.Contains(r.stderr, tc.msg) {
			t.Errorf("%s: exit %d, stderr %q", tc.name, r.code, r.stderr)
		}
	}
	writeFile(t, filepath.Join(dir, "repo", ".wdyapt.lock"), `{"host":"ci","user":"runner","pid":7}`, 0o644)
	writeFile(t, filepath.Join(dir, "other"), "#!/bin/sh\n", 0o755)
	wdyapt(t, map[string]string{"WDYAPT_MAINTAINER": "CI <ci@example.com>"}, "deb", "build", "--name", "other", "--version", "1", "--arch", "amd64",
		"--summary", "x", "--file", filepath.Join(dir, "other")+":/usr/bin/other", "--epoch", "1", "--out", filepath.Join(dir, "build2"), "--quiet")
	r := wdyapt(t, env, "publish", filepath.Join(dir, "build2"))
	if r.code != 75 || !strings.Contains(r.stderr, "locked by another publish") {
		t.Errorf("lock: exit %d, %s", r.code, r.stderr)
	}
	spec.Verified(t, nfr.RNfrHumansAndPipelines)
}

// --json writes exactly one JSON document per command to Stdout.
func TestJSONOutput(t *testing.T) {
	dir, env := pipeline(t)
	r := wdyapt(t, env, "publish", "--create", "--json", "--quiet", filepath.Join(dir, "build"))
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var res struct {
		Suite      string
		Changed    bool
		Added      []struct{ Package, Filename string }
		Signatures []string
	}
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil {
		t.Fatalf("%v: %s", err, r.stdout)
	}
	if res.Suite != "stable" || !res.Changed || len(res.Added) != 1 || len(res.Signatures) != 1 {
		t.Errorf("publish json = %+v", res)
	}
	r = wdyapt(t, env, "repo", "list", "--json", "--trusted-key", filepath.Join(dir, "key.asc"))
	var list struct {
		Checked  bool
		Packages []struct{ Package, Version, Filename string }
	}
	if err := json.Unmarshal([]byte(r.stdout), &list); err != nil || !list.Checked || len(list.Packages) != 1 || list.Packages[0].Package != "tool" {
		t.Errorf("repo list json: %v %+v", err, list)
	}
	r = wdyapt(t, env, "repo", "verify", "--json", "--check-pool", "--trusted-key", filepath.Join(dir, "key.gpg"))
	var verify struct {
		Suites   []string
		Problems []any
	}
	if err := json.Unmarshal([]byte(r.stdout), &verify); err != nil || r.code != 0 || len(verify.Problems) != 0 || len(verify.Suites) != 1 {
		t.Errorf("repo verify json: %d %v %+v %s", r.code, err, verify, r.stderr)
	}
	spec.Verified(t, nfr.RNfrHumansAndPipelines, repo.RRepoList, repo.RRepoVerify)
}
