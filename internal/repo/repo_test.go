package repo

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/deb"
	"github.com/worldiety/wdyapt/internal/debian"
	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/store"
	reqrepo "github.com/worldiety/wdyapt/requirements/fun/repo"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

var testDate = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// fixture copies the state in the wdyhub format (testdata/wdyhub, generated
// with the wdyhub tool and signed with gpg) into a directory.
func fixture(t *testing.T) (string, *openpgp.Keyring) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join("testdata", "wdyhub", "repo")
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dir, rel), 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join("testdata", "wdyhub", "key", "public.asc"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	keys, err := openpgp.ReadKeys(f)
	if err != nil {
		t.Fatal(err)
	}
	return dir, openpgp.NewKeyring(keys...)
}

func open(t *testing.T, dir string) store.Store {
	t.Helper()
	d, err := store.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func newPackage(t *testing.T, name, version, arch string) *Package {
	t.Helper()
	src := filepath.Join(t.TempDir(), "f")
	os.WriteFile(src, []byte(name+version), 0o644)
	built, err := deb.Build(&deb.Manifest{Package: name, Version: version, Architectures: []string{arch},
		Maintainer: "T <t@example.com>", Summary: "test", Files: []deb.File{{Src: src, Dst: "/usr/share/" + name}}}, testDate, deb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := deb.ReadBytes(built[0].Data, false)
	if err != nil {
		t.Fatal(err)
	}
	data := built[0].Data
	return &Package{Info: info, Name: built[0].FileName, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}
}

// The wdyhub state is read and verified: signature from gpg, lists,
// entries.
func TestReadsWdyhubState(t *testing.T) {
	dir, ring := fixture(t)
	for _, suite := range []string{"stable", "dev"} {
		s, err := ReadSuite(context.Background(), open(t, dir), suite, ring)
		if err != nil {
			t.Fatalf("%s: %v", suite, err)
		}
		if !s.Exists || !s.Checked || len(s.Signers) != 1 || s.Release.Get("Origin") != "worldiety" {
			t.Errorf("%s: %+v", suite, s)
		}
		if n := len(List(s, Filter{})); n != 12 {
			t.Errorf("%s: %d packages", suite, n)
		}
	}
	spec.Verified(t, reqrepo.RRepoCheckState)
}

// A package into a wdyhub state: header fields in order and value, all
// previous entries and unchanged lists stay.
func TestWdyhubLayoutIsPreserved(t *testing.T) {
	dir, ring := fixture(t)
	st := open(t, dir)
	s, err := ReadSuite(context.Background(), st, "stable", ring)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Merge(s, []*Package{newPackage(t, "caddy", "2.10.0-1", "arm64")}, MergeOptions{Component: "main", Date: testDate})
	if err != nil {
		t.Fatal(err)
	}
	newRel, err := debian.ParseOne(string(plan.Release))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, f := range newRel {
		keys = append(keys, f.Key)
	}
	if got := strings.Join(keys, " "); got != "Origin Label Suite Codename Date Architectures Components Description Changelogs MD5Sum SHA256" {
		t.Errorf("fields: %s", got)
	}
	for _, f := range []string{"Origin", "Label", "Suite", "Codename", "Architectures", "Components", "Description", "Changelogs"} {
		if newRel.Get(f) != s.Release.Get(f) {
			t.Errorf("%s changed: %q -> %q", f, s.Release.Get(f), newRel.Get(f))
		}
	}
	if newRel.Get("Date") != "Tue, 20 Oct 2026 12:00:00 UTC" {
		t.Errorf("Date = %s", newRel.Get("Date"))
	}
	// Only the arm64 list is new; the lines of the amd64 list stay.
	if len(plan.Indices) != 2 || !strings.HasSuffix(plan.Indices[1].Path, "main/binary-arm64/Packages") {
		t.Fatalf("indices: %v", plan.Indices)
	}
	oldSHA := s.Release.Get("SHA256")
	for _, line := range debian.Lines(oldSHA) {
		if strings.HasSuffix(line, "binary-amd64/Packages") && !strings.Contains(newRel.Get("SHA256"), line) {
			t.Errorf("unchanged line %q dropped", line)
		}
	}
	old, _ := os.ReadFile(filepath.Join(dir, "dists/stable/main/binary-arm64/Packages"))
	oldEntries, _ := debian.Parse(string(old))
	for _, e := range oldEntries {
		if !strings.Contains(string(plan.Indices[1].Data), e.String()) {
			t.Errorf("entry %s not kept verbatim", e.Get("Filename"))
		}
	}
	entries, _ := debian.Parse(string(plan.Indices[1].Data))
	if len(entries) != 7 {
		t.Errorf("%d entries, want 7", len(entries))
	}
	spec.Verified(t, reqrepo.RRepoKeepReleaseFields)
}

// Fields of an existing suite cannot be changed.
func TestFieldsOfExistingSuiteAreRefused(t *testing.T) {
	dir, ring := fixture(t)
	s, err := ReadSuite(context.Background(), open(t, dir), "stable", ring)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Merge(s, []*Package{newPackage(t, "caddy", "1", "amd64")}, MergeOptions{Label: "Other", Date: testDate})
	if err == nil || !strings.Contains(err.Error(), "never changes it") {
		t.Errorf("changed label: %v", err)
	}
	if _, err := Merge(s, []*Package{newPackage(t, "caddy", "1", "amd64")}, MergeOptions{Label: "worldiety Hub", Date: testDate}); err != nil {
		t.Errorf("same label: %v", err)
	}
	spec.Verified(t, reqrepo.RRepoKeepReleaseFields)
}

// The same state, the same packages and the same date yield the same lists
// and the same Release, regardless of the order of the packages.
func TestIndicesAreReproducible(t *testing.T) {
	dir, ring := fixture(t)
	s, err := ReadSuite(context.Background(), open(t, dir), "stable", ring)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := newPackage(t, "caddy", "2", "amd64"), newPackage(t, "zeta", "1", "all"), newPackage(t, "caddy", "1", "amd64")
	p1, err := Merge(s, []*Package{a, b, c}, MergeOptions{Date: testDate})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Merge(s, []*Package{c, b, a}, MergeOptions{Date: testDate})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p1.Release, p2.Release) || len(p1.Indices) != len(p2.Indices) {
		t.Fatal("Release differs")
	}
	for i := range p1.Indices {
		if !bytes.Equal(p1.Indices[i].Data, p2.Indices[i].Data) {
			t.Errorf("%s differs", p1.Indices[i].Path)
		}
	}
	entries, _ := debian.Parse(string(p1.Indices[1].Data))
	var order []string
	for _, e := range entries {
		if e.Get("Package") == "caddy" {
			order = append(order, e.Get("Version"))
		}
	}
	if strings.Join(order, " ") != "1 2" {
		t.Errorf("caddy versions in order %v", order)
	}
	spec.Verified(t, nfr.RNfrReproducibility)
}

// A package with the same name, version and architecture but different
// content is never replaced; with the same content it is unchanged.
func TestMergeNeverReplaces(t *testing.T) {
	dir, ring := fixture(t)
	s, err := ReadSuite(context.Background(), open(t, dir), "stable", ring)
	if err != nil {
		t.Fatal(err)
	}
	fake := newPackage(t, "wdyhub-runner", "1.4.0", "amd64")
	if _, err := Merge(s, []*Package{fake}, MergeOptions{Date: testDate}); err == nil || !strings.Contains(err.Error(), "never replaced") {
		t.Errorf("replacement: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "pool/main/w/wdyhub-runner/wdyhub-runner_1.4.0_amd64.deb"))
	info, _ := deb.ReadBytes(data, false)
	plan, err := Merge(s, []*Package{{Info: info, Name: "same"}}, MergeOptions{Date: testDate})
	if err != nil || plan.Changed() || len(plan.Unchanged) != 1 {
		t.Errorf("same bytes: %v %+v", err, plan)
	}
	spec.Verified(t, reqrepo.RRepoNeverReplace)
}

// repo list returns the packages filtered and sorted.
func TestListSuite(t *testing.T) {
	dir, ring := fixture(t)
	s, err := ReadSuite(context.Background(), open(t, dir), "dev", ring)
	if err != nil {
		t.Fatal(err)
	}
	got := List(s, Filter{Arch: "arm64", Package: "wdyhub-proxy"})
	if len(got) != 1 || got[0].Filename != "pool/main/w/wdyhub-proxy/wdyhub-proxy_1.5.0~dev.20261019120000.abcdef12_arm64.deb" || got[0].Size == 0 || len(got[0].SHA256) != 64 {
		t.Errorf("list = %+v", got)
	}
	all := List(s, Filter{})
	if all[0].Package != "wdyhub-builder" || all[0].Architecture != "amd64" || all[1].Architecture != "arm64" {
		t.Errorf("order: %+v", all[:2])
	}
	spec.Verified(t, reqrepo.RRepoList)
}

// repo verify finds all defects: missing and wrong pool files, changed
// lists, temporary files and a lock.
func TestVerifyFindsProblems(t *testing.T) {
	dir, ring := fixture(t)
	st := open(t, dir)
	res, err := Verify(context.Background(), st, ring, VerifyOptions{CheckPool: true})
	if err != nil || len(res.Problems) != 0 || len(res.Suites) != 2 || res.Packages != 24 {
		t.Fatalf("clean fixture: %v %+v", err, res)
	}
	os.Remove(filepath.Join(dir, "pool/main/w/wdyhub-web/wdyhub-web_1.4.0_amd64.deb"))
	os.WriteFile(filepath.Join(dir, "pool/main/w/wdyhub-web/wdyhub-web_1.4.0_arm64.deb"), []byte("short"), 0o644)
	f := filepath.Join(dir, "pool/main/w/wdyhub-proxy/wdyhub-proxy_1.4.0_amd64.deb")
	data, _ := os.ReadFile(f)
	data[len(data)-1] ^= 1
	os.WriteFile(f, data, 0o644)
	list := filepath.Join(dir, "dists/dev/main/binary-amd64/Packages")
	ld, _ := os.ReadFile(list)
	os.WriteFile(list, append(ld, '\n'), 0o644)
	os.WriteFile(filepath.Join(dir, "dists/stable/InRelease"+store.TempMarker+"abc.tmp"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, LockFile), []byte(`{"host":"ci"}`), 0o644)

	res, err = Verify(context.Background(), st, ring, VerifyOptions{CheckPool: true})
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, p := range res.Problems {
		all = append(all, p.String())
	}
	text := strings.Join(all, "\n")
	for _, want := range []string{
		"wdyhub-web_1.4.0_amd64.deb: missing",
		"wdyhub-web_1.4.0_arm64.deb: has 5 bytes",
		"wdyhub-proxy_1.4.0_amd64.deb: does not match its SHA256",
		"suite dev: dists/dev/main/binary-amd64/Packages has",
		"InRelease.wdyapt-abc.tmp: temporary file",
		".wdyapt.lock: a lock is held",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	res, _ = Verify(context.Background(), st, ring, VerifyOptions{Suites: []string{"stable"}})
	for _, p := range res.Problems {
		if strings.Contains(p.String(), "proxy") {
			t.Errorf("without --check-pool the content is checked: %s", p)
		}
	}
	spec.Verified(t, reqrepo.RRepoVerify)
}
