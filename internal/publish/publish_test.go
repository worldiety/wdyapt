package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/deb"
	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/repo"
	"github.com/worldiety/wdyapt/internal/store"
	"github.com/worldiety/wdyapt/requirements/dec"
	reqkey "github.com/worldiety/wdyapt/requirements/fun/key"
	reqrepo "github.com/worldiety/wdyapt/requirements/fun/repo"
)

var testDate = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// recorder is a directory storage that records every writing operation and
// lets one fail on request.
type recorder struct {
	*store.Dir
	mu   sync.Mutex
	ops  []string
	fail func(op, name string) error
}

func (r *recorder) log(op, name string) error {
	r.mu.Lock()
	r.ops = append(r.ops, op+" "+name)
	r.mu.Unlock()
	if r.fail != nil {
		return r.fail(op, name)
	}
	return nil
}

func (r *recorder) WriteTemp(ctx context.Context, name string, rd io.Reader) (string, error) {
	if err := r.log("write", name); err != nil {
		return "", err
	}
	return r.Dir.WriteTemp(ctx, name, rd)
}

func (r *recorder) Rename(ctx context.Context, from, to string) error {
	if err := r.log("rename", to); err != nil {
		return err
	}
	return r.Dir.Rename(ctx, from, to)
}

func (r *recorder) Remove(ctx context.Context, name string) error {
	r.log("remove", name)
	return r.Dir.Remove(ctx, name)
}

func (r *recorder) CreateExclusive(ctx context.Context, name string, data []byte) error {
	if err := r.log("create", name); err != nil {
		return err
	}
	return r.Dir.CreateExclusive(ctx, name, data)
}

func newRecorder(t *testing.T, dir string) *recorder {
	t.Helper()
	d, err := store.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &recorder{Dir: d}
}

var (
	keyOnce  sync.Once
	keyA     *openpgp.Entity
	keyB     *openpgp.Entity
	keyError error
)

// keys returns two signing keys, the same for all tests.
func keys(t *testing.T) (*openpgp.Entity, *openpgp.Entity) {
	t.Helper()
	keyOnce.Do(func() {
		if keyA, keyError = openpgp.Generate("Key A <a@example.com>", testDate.Add(-time.Hour), 0); keyError != nil {
			return
		}
		keyB, keyError = openpgp.Generate("Key B <b@example.com>", testDate.Add(-time.Hour), 0)
	})
	if keyError != nil {
		t.Fatal(keyError)
	}
	return keyA, keyB
}

// pkg builds a package and returns it for publishing.
func pkg(t *testing.T, name, version, arch, content string) *repo.Package {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "file")
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	built, err := deb.Build(&deb.Manifest{
		Package: name, Version: version, Architectures: []string{arch},
		Maintainer: "Test <test@example.com>", Summary: "Test package " + name,
		Files: []deb.File{{Src: src, Dst: "/usr/share/" + name + "/file"}},
	}, testDate, deb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	data := built[0].Data
	info, err := deb.ReadBytes(data, false)
	if err != nil {
		t.Fatal(err)
	}
	return &repo.Package{Info: info, Name: built[0].FileName, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}
}

func input(t *testing.T, suite string, pkgs ...*repo.Package) Input {
	t.Helper()
	a, _ := keys(t)
	return Input{
		Suite: suite, Component: "main", Packages: pkgs,
		Signers: []*openpgp.Entity{a}, Keyring: openpgp.NewKeyring(a),
		Date: testDate, Lock: LockInfo{Host: "test", User: "tester", PID: 1, Suite: suite, Version: "test"},
	}
}

func run(t *testing.T, st store.Store, in Input) *Result {
	t.Helper()
	res, err := Run(context.Background(), st, in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func readSuite(t *testing.T, dir, suite string) *repo.SuiteState {
	t.Helper()
	a, _ := keys(t)
	d, _ := store.OpenDir(dir)
	s, err := repo.ReadSuite(context.Background(), d, suite, openpgp.NewKeyring(a))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tree returns all files under dir with their content.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	return out
}

// A new suite is created with --create: pool, lists per architecture,
// Release with the fields of a new suite, signed.
func TestPublishIntoNewSuite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	in := input(t, "stable", pkg(t, "alpha", "1.0-1", "amd64", "a"), pkg(t, "beta", "2.0", "arm64", "b"))
	in.Create, in.Origin, in.Label, in.Description = true, "Example", "Example Repo", "Example packages"
	res := run(t, newRecorder(t, dir), in)
	if !res.Changed || len(res.Added) != 2 || len(res.Uploaded) != 2 {
		t.Fatalf("result = %+v", res)
	}
	files := tree(t, dir)
	for _, f := range []string{
		"pool/main/a/alpha/alpha_1.0-1_amd64.deb", "pool/main/b/beta/beta_2.0_arm64.deb",
		"dists/stable/main/binary-amd64/Packages", "dists/stable/main/binary-amd64/Packages.gz",
		"dists/stable/main/binary-arm64/Packages", "dists/stable/main/binary-arm64/Packages.gz",
		"dists/stable/Release", "dists/stable/Release.gpg", "dists/stable/InRelease",
	} {
		if _, ok := files[f]; !ok {
			t.Errorf("%s missing", f)
		}
	}
	if _, ok := files[repo.LockFile]; ok {
		t.Error("the lock is left")
	}
	rel := files["dists/stable/Release"]
	want := "Origin: Example\nLabel: Example Repo\nSuite: stable\nCodename: stable\nDate: Tue, 20 Oct 2026 12:00:00 UTC\nArchitectures: amd64 arm64\nComponents: main\nDescription: Example packages\nChangelogs: no\nMD5Sum:\n"
	if !strings.HasPrefix(rel, want) || !strings.Contains(rel, "\nSHA256:\n") {
		t.Errorf("Release:\n%s", rel)
	}
	amd := files["dists/stable/main/binary-amd64/Packages"]
	if !strings.Contains(amd, "Package: alpha\n") || strings.Contains(amd, "beta") || !strings.Contains(amd, "Filename: pool/main/a/alpha/alpha_1.0-1_amd64.deb\nSize: ") {
		t.Errorf("amd64 Packages:\n%s", amd)
	}
	s := readSuite(t, dir, "stable")
	if len(repo.List(s, repo.Filter{})) != 2 {
		t.Errorf("listed %v", repo.List(s, repo.Filter{}))
	}
	spec.Verified(t, reqrepo.RRepoPublishPackages)
}

// A package for all is in every list, also in one that is added later with
// a new architecture.
func TestArchAllInEveryList(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "docs", "1", "all", "d"))
	in.Create, in.Architectures = true, []string{"amd64", "arm64"}
	run(t, newRecorder(t, dir), in)
	in = input(t, "stable", pkg(t, "tool", "1", "riscv64", "t"))
	in.Date = testDate.Add(time.Hour)
	res := run(t, newRecorder(t, dir), in)
	if len(res.Added) != 1 {
		t.Fatalf("added %v", res.Added)
	}
	files := tree(t, dir)
	for _, a := range []string{"amd64", "arm64", "riscv64"} {
		if !strings.Contains(files["dists/stable/main/binary-"+a+"/Packages"], "Package: docs\n") {
			t.Errorf("docs missing in the %s list", a)
		}
	}
	if !strings.Contains(files["dists/stable/Release"], "Architectures: amd64 arm64 riscv64\n") {
		t.Errorf("Release:\n%s", files["dists/stable/Release"])
	}
	if c := strings.Count(files["dists/stable/main/binary-amd64/Packages"], "Package: "); c != 1 {
		t.Errorf("amd64 has %d entries", c)
	}
	spec.Verified(t, reqrepo.RRepoPublishPackages)
}

// Without --create no suite is created; a new suite only for all needs
// architectures.
func TestMissingSuiteNeedsCreate(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(context.Background(), newRecorder(t, dir), input(t, "stabel", pkg(t, "alpha", "1", "amd64", "a")))
	if err == nil || !strings.Contains(err.Error(), "--create") {
		t.Errorf("no --create: %v", err)
	}
	in := input(t, "stable", pkg(t, "docs", "1", "all", "d"))
	in.Create = true
	if _, err := Run(context.Background(), newRecorder(t, dir), in); err == nil || !strings.Contains(err.Error(), "--architectures") {
		t.Errorf("only all: %v", err)
	}
	if files := tree(t, dir); len(files) != 0 {
		t.Errorf("files written: %v", files)
	}
	_, err = Run(context.Background(), newRecorder(t, filepath.Join(dir, "missing")), input(t, "stable", pkg(t, "alpha", "1", "amd64", "a")))
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing root: %v", err)
	}
	spec.Verified(t, reqrepo.RRepoPublishPackages)
}

// The same package with different content is never replaced; with the
// same bytes there is nothing to do and nothing is written.
func TestNeverReplacesAndRepublishIsNoop(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	before := tree(t, dir)

	rec := newRecorder(t, dir)
	again := input(t, "stable", in.Packages[0])
	again.Date = testDate.Add(time.Hour)
	res := run(t, rec, again)
	if res.Changed || len(res.Unchanged) != 1 || len(res.Uploaded) != 0 {
		t.Errorf("republish: %+v", res)
	}
	if !maps(before, tree(t, dir)) {
		t.Error("republishing changed files")
	}
	for _, op := range rec.ops {
		if strings.HasPrefix(op, "write") || strings.HasPrefix(op, "rename") {
			t.Errorf("republishing wrote: %s", op)
		}
	}

	other := input(t, "stable", pkg(t, "alpha", "1", "amd64", "other content"))
	_, err := Run(context.Background(), newRecorder(t, dir), other)
	if err == nil || !strings.Contains(err.Error(), "never replaced") {
		t.Errorf("replacement: %v", err)
	}
	if !maps(before, tree(t, dir)) {
		t.Error("a refused replacement changed files")
	}
	spec.Verified(t, reqrepo.RRepoNeverReplace)
}

func maps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// A changed list and a foreign signature stop the publication before it
// writes anything.
func TestTamperedListIsRejected(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	list := filepath.Join(dir, "dists/stable/main/binary-amd64/Packages")
	data, _ := os.ReadFile(list)
	os.WriteFile(list, bytes.Replace(data, []byte("Package: alpha"), []byte("Package: alphb"), 1), 0o644)
	rec := newRecorder(t, dir)
	_, err := Run(context.Background(), rec, input(t, "stable", pkg(t, "beta", "1", "amd64", "b")))
	var ce *repo.ChecksumError
	if !errors.As(err, &ce) || ce.File != "main/binary-amd64/Packages" {
		t.Fatalf("tampered list: %v", err)
	}
	for _, op := range rec.ops {
		if strings.HasPrefix(op, "write") {
			t.Errorf("wrote after a failed check: %s", op)
		}
	}
	spec.Verified(t, reqrepo.RRepoCheckState)
}

func TestUntrustedSignatureIsRejected(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	_, b := keys(t)
	other := input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	other.Signers, other.Keyring = []*openpgp.Entity{b}, openpgp.NewKeyring(b)
	_, err := Run(context.Background(), newRecorder(t, dir), other)
	if err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("foreign key: %v", err)
	}
	// Release without signature.
	os.Remove(filepath.Join(dir, "dists/stable/InRelease"))
	os.Remove(filepath.Join(dir, "dists/stable/Release.gpg"))
	if _, err := Run(context.Background(), newRecorder(t, dir), input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned: %v", err)
	}
	// Lists without Release.
	os.Remove(filepath.Join(dir, "dists/stable/Release"))
	if _, err := Run(context.Background(), newRecorder(t, dir), input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))); err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("lists without Release: %v", err)
	}
	spec.Verified(t, reqrepo.RRepoCheckState)
}

// InRelease and Release.gpg carry one signature per key with SHA-512; the
// date always increases, even if --date is older.
func TestReleaseIsSignedAndDateNeverGoesBack(t *testing.T) {
	dir := t.TempDir()
	a, b := keys(t)
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create, in.Signers, in.Keyring = true, []*openpgp.Entity{a, b}, openpgp.NewKeyring(a, b)
	res := run(t, newRecorder(t, dir), in)
	if len(res.Signatures) != 2 {
		t.Errorf("signatures %v", res.Signatures)
	}
	files := tree(t, dir)
	ring := openpgp.NewKeyring(a, b)
	text, infos, err := ring.VerifyCleartext([]byte(files["dists/stable/InRelease"]))
	if err != nil || string(text) != files["dists/stable/Release"] || len(infos) != 2 || infos[0].Hash != "SHA512" {
		t.Fatalf("InRelease: %v %v", infos, err)
	}
	if infos, err := ring.VerifyDetached([]byte(files["dists/stable/Release"]), []byte(files["dists/stable/Release.gpg"])); err != nil || len(infos) != 2 {
		t.Fatalf("Release.gpg: %v %v", infos, err)
	}
	older := input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	older.Signers, older.Keyring, older.Date = []*openpgp.Entity{a, b}, ring, testDate.Add(-48*time.Hour)
	res = run(t, newRecorder(t, dir), older)
	if res.Date != "Tue, 20 Oct 2026 12:00:01 UTC" {
		t.Errorf("Date = %s", res.Date)
	}
	// Two runs in the same second: Date moves into the future, the signature
	// never does; sqv rejects signatures from the future.
	now := time.Now().Truncate(time.Second)
	for i := 0; i < 2; i++ {
		same := input(t, "stable", pkg(t, fmt.Sprintf("same%d", i), "1", "amd64", "s"))
		same.Signers, same.Keyring, same.Date = []*openpgp.Entity{a, b}, ring, now
		run(t, newRecorder(t, dir), same)
	}
	files = tree(t, dir)
	_, infos, err = ring.VerifyCleartext([]byte(files["dists/stable/InRelease"]))
	if err != nil || infos[0].Created.After(time.Now()) || !strings.Contains(files["dists/stable/Release"], repo.FormatDate(now.Add(time.Second))) {
		t.Errorf("signature time %v, Release:\n%s", infos, files["dists/stable/Release"])
	}
	spec.Verified(t, reqrepo.RRepoSign)
}

// The dry run shows the plan and writes nothing, not even a lock.
func TestDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	before := tree(t, dir)
	rec := newRecorder(t, dir)
	out := t.TempDir()
	dry := input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	dry.DryRun, dry.OutDir, dry.Date = true, out, testDate.Add(time.Hour)
	res := run(t, rec, dry)
	if !res.DryRun || !res.Changed || len(res.Uploaded) != 1 || !strings.Contains(res.Release, "SHA256:") {
		t.Errorf("dry run: %+v", res)
	}
	if len(rec.ops) != 0 || !maps(before, tree(t, dir)) {
		t.Errorf("dry run wrote: %v", rec.ops)
	}
	if _, err := os.Stat(filepath.Join(out, "dists/stable/InRelease")); err != nil {
		t.Errorf("--out: %v", err)
	}
	spec.Verified(t, reqrepo.RRepoDryRun)
}

// Many versions in a row: all stay, nothing is removed, and no operation
// deletes a published file.
func TestManyVersionsAreKeptAndNothingIsRemoved(t *testing.T) {
	dir := t.TempDir()
	var removed []string
	for i := 1; i <= 7; i++ {
		in := input(t, "dev", pkg(t, "alpha", fmt.Sprintf("1.0~dev.%d", i), "amd64", fmt.Sprint(i)))
		in.Create, in.Date = true, testDate.Add(time.Duration(i)*time.Minute)
		rec := newRecorder(t, dir)
		run(t, rec, in)
		for _, op := range rec.ops {
			if strings.HasPrefix(op, "remove") && !strings.HasSuffix(op, repo.LockFile) {
				removed = append(removed, op)
			}
		}
	}
	s := readSuite(t, dir, "dev")
	if n := len(repo.List(s, repo.Filter{})); n != 7 {
		t.Errorf("%d versions listed, want 7", n)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "pool/main/a/alpha"))
	if len(entries) != 7 {
		t.Errorf("%d pool files, want 7", len(entries))
	}
	if len(removed) > 0 {
		t.Errorf("removed: %v", removed)
	}
	spec.Verified(t, dec.RDecNoDeletion)
}

// First pool, then lists and Release as temporary files, then rename:
// Packages.gz before Packages, Release, Release.gpg and InRelease last.
func TestUploadOrder(t *testing.T) {
	dir := t.TempDir()
	rec := newRecorder(t, dir)
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, rec, in)
	var ops []string
	for _, op := range rec.ops {
		if !strings.HasSuffix(op, repo.LockFile) {
			ops = append(ops, op)
		}
	}
	want := []string{
		"write pool/main/a/alpha/alpha_1_amd64.deb",
		"rename pool/main/a/alpha/alpha_1_amd64.deb",
		"write dists/stable/main/binary-amd64/Packages.gz",
		"write dists/stable/main/binary-amd64/Packages",
		"write dists/stable/Release",
		"write dists/stable/Release.gpg",
		"write dists/stable/InRelease",
		"rename dists/stable/main/binary-amd64/Packages.gz",
		"rename dists/stable/main/binary-amd64/Packages",
		"rename dists/stable/Release",
		"rename dists/stable/Release.gpg",
		"rename dists/stable/InRelease",
	}
	if !slices.Equal(ops, want) {
		t.Errorf("operations:\n%s\nwant:\n%s", strings.Join(ops, "\n"), strings.Join(want, "\n"))
	}
	if rec.ops[0] != "create "+repo.LockFile || rec.ops[len(rec.ops)-1] != "remove "+repo.LockFile {
		t.Errorf("lock not first and last: %v", rec.ops)
	}
	spec.Verified(t, dec.RDecAtomicPublishing)
}

// If the upload aborts, no final name holds a partial file, the temporary
// files are removed and lists and Release are unchanged; a pool file that
// was already uploaded completely may stay, because nothing references it.
func TestAbortLeavesNoPartialFile(t *testing.T) {
	for _, failAt := range []string{"rename pool/main/b/beta/beta_1_amd64.deb", "write dists/stable/Release", "write dists/stable/InRelease"} {
		dir := t.TempDir()
		in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
		in.Create = true
		run(t, newRecorder(t, dir), in)
		before := tree(t, dir)
		rec := newRecorder(t, dir)
		rec.fail = func(op, name string) error {
			if op+" "+name == failAt {
				return errors.New("connection lost")
			}
			return nil
		}
		beta := pkg(t, "beta", "1", "amd64", "b")
		_, err := Run(context.Background(), rec, input(t, "stable", beta))
		if err == nil || !strings.Contains(err.Error(), "connection lost") {
			t.Fatalf("%s: %v", failAt, err)
		}
		r, _ := beta.Open()
		complete, _ := io.ReadAll(r)
		after := tree(t, dir)
		for name, data := range after {
			if store.IsTemp(name) {
				t.Errorf("%s: temporary file %s left", failAt, name)
			}
			if _, ok := before[name]; !ok && !(name == "pool/main/b/beta/beta_1_amd64.deb" && data == string(complete)) {
				t.Errorf("%s: new file %s under its final name", failAt, name)
			}
		}
		for name, data := range before {
			if after[name] != data {
				t.Errorf("%s: %s changed", failAt, name)
			}
		}
	}
	spec.Verified(t, dec.RDecAtomicPublishing)
}

// If switching aborts after the lists, the next run completes the signed
// state of the aborted one and adds afterwards.
func TestInterruptedSwitchIsCompleted(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	rec := newRecorder(t, dir)
	rec.fail = func(op, name string) error {
		if op == "rename" && name == "dists/stable/Release" {
			return errors.New("connection lost")
		}
		return nil
	}
	second := input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	second.Date = testDate.Add(time.Hour)
	if _, err := Run(context.Background(), rec, second); err == nil || !strings.Contains(err.Error(), "run publish again") {
		t.Fatalf("interrupted switch: %v", err)
	}
	var msgs []string
	third := input(t, "stable", second.Packages[0])
	third.Date = testDate.Add(2 * time.Hour)
	third.Say = func(f string, a ...any) { msgs = append(msgs, fmt.Sprintf(f, a...)) }
	res := run(t, newRecorder(t, dir), third)
	if len(res.Unchanged) != 1 || res.Changed {
		t.Errorf("completing run: %+v", res)
	}
	if !strings.Contains(strings.Join(msgs, "\n"), "completing it") {
		t.Errorf("messages: %v", msgs)
	}
	s := readSuite(t, dir, "stable")
	if n := len(repo.List(s, repo.Filter{})); n != 2 {
		t.Errorf("%d packages after completing", n)
	}
	for name := range tree(t, dir) {
		if store.IsTemp(name) {
			t.Errorf("temporary file %s left", name)
		}
	}
	spec.Verified(t, dec.RDecAtomicPublishing)
}

// A taken lock ends the run as a temporary failure, also after waiting;
// --break-lock removes it.
func TestLockHeld(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	lock := `{"host":"ci","user":"runner","pid":42,"started":"2026-10-20T11:00:00Z","version":"0.1.0","suite":"dev"}`
	os.WriteFile(filepath.Join(dir, repo.LockFile), []byte(lock), 0o644)
	waiting := input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	waiting.WaitForLock = 50 * time.Millisecond
	_, err := Run(context.Background(), newRecorder(t, dir), waiting)
	if !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), "runner@ci, pid 42, suite dev") {
		t.Fatalf("held lock: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, repo.LockFile)); string(data) != lock {
		t.Error("a held lock was removed")
	}
	breaking := input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	breaking.BreakLock = true
	if res := run(t, newRecorder(t, dir), breaking); len(res.Added) != 1 {
		t.Errorf("--break-lock: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, repo.LockFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Error("lock left after --break-lock")
	}
	spec.Verified(t, dec.RDecLockAndConflictDetection)
}

// If another run changes the suite while this one uploads, this one does
// not switch, cleans up its temporary files and reports ErrBusy.
func TestConcurrentChangeDetected(t *testing.T) {
	dir := t.TempDir()
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	rec := newRecorder(t, dir)
	rec.fail = func(op, name string) error {
		if op == "write" && name == "dists/stable/InRelease" {
			// A foreign tool without a lock is switching right now.
			f := filepath.Join(dir, "dists/stable/InRelease")
			data, _ := os.ReadFile(f)
			os.WriteFile(f, append(data, '\n'), 0o644)
		}
		return nil
	}
	before := tree(t, dir)
	_, err := Run(context.Background(), rec, input(t, "stable", pkg(t, "beta", "1", "amd64", "b")))
	if !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), "changed while publishing") {
		t.Fatalf("concurrent change: %v", err)
	}
	after := tree(t, dir)
	for name := range after {
		if store.IsTemp(name) {
			t.Errorf("temporary file %s left", name)
		}
	}
	if after["dists/stable/Release"] != before["dists/stable/Release"] {
		t.Error("switched despite the change")
	}
	spec.Verified(t, dec.RDecLockAndConflictDetection)
}

// Key rotation: the state is signed with the old key, which is given as
// trusted key; signing happens with the new one.
func TestAcceptsPreviousKey(t *testing.T) {
	dir := t.TempDir()
	a, b := keys(t)
	in := input(t, "stable", pkg(t, "alpha", "1", "amd64", "a"))
	in.Create = true
	run(t, newRecorder(t, dir), in)
	next := input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	next.Signers, next.Keyring = []*openpgp.Entity{b}, openpgp.NewKeyring(b, a)
	res := run(t, newRecorder(t, dir), next)
	if len(res.Signatures) != 1 || res.Signatures[0] != b.Fingerprint().String() {
		t.Errorf("signatures %v", res.Signatures)
	}
	d, _ := store.OpenDir(dir)
	if _, err := repo.ReadSuite(context.Background(), d, "stable", openpgp.NewKeyring(b)); err != nil {
		t.Errorf("new key only: %v", err)
	}
	spec.Verified(t, reqkey.RKeyRotation)
}

// Pool files referenced by another suite are reused; a leftover without a
// list and with different content is replaced.
func TestPoolFilesAreReused(t *testing.T) {
	dir := t.TempDir()
	p := pkg(t, "alpha", "1", "amd64", "a")
	in := input(t, "stable", p)
	in.Create = true
	run(t, newRecorder(t, dir), in)
	dev := input(t, "dev", p)
	dev.Create = true
	res := run(t, newRecorder(t, dir), dev)
	if len(res.Uploaded) != 0 || len(res.Reused) != 1 {
		t.Errorf("reuse: %+v", res)
	}
	leftover := filepath.Join(dir, "pool/main/b/beta/beta_1_amd64.deb")
	os.MkdirAll(filepath.Dir(leftover), 0o755)
	os.WriteFile(leftover, []byte("half a package"), 0o644)
	var warned []string
	in = input(t, "stable", pkg(t, "beta", "1", "amd64", "b"))
	in.Warn = func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) }
	res = run(t, newRecorder(t, dir), in)
	if len(res.Uploaded) != 1 || len(warned) != 1 || !strings.Contains(warned[0], "no suite names it") {
		t.Errorf("leftover: %+v %v", res, warned)
	}
	spec.Verified(t, reqrepo.RRepoPublishPackages)
}
