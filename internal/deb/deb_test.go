package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/debian"
	reqpkg "github.com/worldiety/wdyapt/requirements/fun/pkg"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

var testEpoch = time.Unix(1791000000, 0).UTC()

// fakeELF is an ELF header for machine; with interp also a program header
// PT_INTERP, as dynamically linked programs carry it.
func fakeELF(t *testing.T, machine elf.Machine, interp string) []byte {
	t.Helper()
	h := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Phentsize: 56, Shentsize: 64}
	copy(h.Ident[:], "\x7fELF")
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	if interp != "" {
		h.Phoff, h.Phnum = 64, 1
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, h); err != nil {
		t.Fatal(err)
	}
	if interp != "" {
		p := elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 64 + 56, Filesz: uint64(len(interp) + 1), Memsz: uint64(len(interp) + 1)}
		if err := binary.Write(&b, binary.LittleEndian, p); err != nil {
			t.Fatal(err)
		}
		b.WriteString(interp + "\x00")
	}
	b.WriteString("program body")
	return b.Bytes()
}

// workdir creates source files for the tests.
func workdir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("downloads/hello_linux_amd64", fakeELF(t, elf.EM_X86_64, ""), 0o755)
	write("downloads/hello_linux_arm64", fakeELF(t, elf.EM_AARCH64, ""), 0o755)
	write("downloads/hello-x86_64", fakeELF(t, elf.EM_X86_64, ""), 0o755)
	write("downloads/hello-aarch64", fakeELF(t, elf.EM_AARCH64, ""), 0o755)
	write("hello.service", []byte("[Service]\nExecStart=/usr/bin/hello\n"), 0o644)
	write("hello.conf", []byte("greeting=hi\n"), 0o644)
	write("scripts/postinst", []byte("#!/bin/sh\nset -e\necho installed\n"), 0o755)
	write("scripts/prerm", []byte("#!/bin/sh\nexit 0\n"), 0o755)
	write("share/doc/README", []byte("readme\n"), 0o644)
	write("share/bin/tool", []byte("#!/bin/sh\n"), 0o700)
	return dir
}

func sampleManifest(dir string) *Manifest {
	return &Manifest{
		Package:       "hello",
		Version:       "1:2.10.0~rc1-1",
		Architectures: []string{"amd64", "arm64"},
		Maintainer:    "worldiety GmbH <support@worldiety.de>",
		Summary:       "Says hello",
		Description:   "Hello greets the world. " + strings.Repeat("It does so politely and at length. ", 4) + "\n\nSecond paragraph.\n\n  hello --loud\n  hello --quiet",
		Homepage:      "https://example.com/hello",
		Section:       "utils",
		Depends:       []string{"libc6 (>= 2.34)", "adduser | passwd"},
		Recommends:    []string{"curl"},
		Files: []File{
			{Src: "downloads/hello_linux_{arch}", Dst: "/usr/bin/hello", Mode: "0755"},
			{Src: "downloads/hello-{uname}", Dst: "/usr/libexec/hello/hello-uname"},
			{Src: "hello.service", Dst: "/usr/lib/systemd/system/hello.service"},
			{Src: "hello.conf", Dst: "/etc/hello/hello.conf", Mode: "0640"},
			{Src: "share/", Dst: "/usr/share/hello"},
		},
		Directories: []Directory{{Path: "/var/lib/hello", Mode: "0750"}},
		Symlinks:    []Symlink{{Path: "/usr/sbin/hello", Target: "/usr/bin/hello"}},
		Conffiles:   []string{"/etc/hello/hello.conf"},
		Scripts:     Scripts{Postinst: "scripts/postinst", Prerm: "scripts/prerm"},
		Fields:      map[string]string{"X-Origin-URL": "https://example.com/releases"},
		Dir:         dir,
	}
}

// tarFile is an entry of a tar archive in the package.
type tarFile struct {
	Header *tar.Header
	Data   string
}

// dpkgView is a package, taken apart the way dpkg reads it.
type dpkgView struct {
	Members []string
	Control map[string]tarFile
	Data    map[string]tarFile
	Order   []string
}

// parseLikeDpkg takes a package apart the way dpkg reads it and checks the
// format on the way: ar headers, order, debian-binary, tar entries with
// "./", root:root, the timestamp and gzip without time.
func parseLikeDpkg(t *testing.T, deb []byte) dpkgView {
	t.Helper()
	if !bytes.HasPrefix(deb, []byte("!<arch>\n")) {
		t.Fatalf("no ar archive")
	}
	r := deb[8:]
	var out dpkgView
	members := map[string][]byte{}
	for len(r) > 0 {
		if len(r) < 60 {
			t.Fatalf("truncated ar header")
		}
		h := string(r[:60])
		if h[58:60] != "`\n" {
			t.Fatalf("ar header %q lacks its end", h)
		}
		name := strings.TrimRight(h[:16], " ")
		if mtime := strings.TrimSpace(h[16:28]); mtime != strconv.FormatInt(testEpoch.Unix(), 10) {
			t.Errorf("%s: ar mtime %s, want the epoch", name, mtime)
		}
		if uid, gid, mode := strings.TrimSpace(h[28:34]), strings.TrimSpace(h[34:40]), strings.TrimSpace(h[40:48]); uid != "0" || gid != "0" || mode != "100644" {
			t.Errorf("%s: ar owner %s:%s mode %s", name, uid, gid, mode)
		}
		size, err := strconv.Atoi(strings.TrimSpace(h[48:58]))
		if err != nil {
			t.Fatalf("%s: ar size: %v", name, err)
		}
		r = r[60:]
		members[name] = r[:size]
		out.Members = append(out.Members, name)
		r = r[size:]
		if size%2 == 1 {
			if r[0] != '\n' {
				t.Fatalf("%s: odd member not padded with a newline", name)
			}
			r = r[1:]
		}
	}
	if strings.Join(out.Members, " ") != "debian-binary control.tar.gz data.tar.gz" {
		t.Errorf("members = %v", out.Members)
	}
	if got := string(members["debian-binary"]); got != "2.0\n" {
		t.Errorf("debian-binary = %q", got)
	}
	out.Control, _ = parseTarGz(t, members["control.tar.gz"])
	out.Data, out.Order = parseTarGz(t, members["data.tar.gz"])
	return out
}

func parseTarGz(t *testing.T, data []byte) (map[string]tarFile, []string) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() || zr.Name != "" {
		t.Errorf("gzip header carries time %v and name %q", zr.ModTime, zr.Name)
	}
	tr := tar.NewReader(zr)
	files := map[string]tarFile{}
	var order []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(h.Name, "./") {
			t.Errorf("%s: name without ./", h.Name)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "root" || h.Gname != "root" {
			t.Errorf("%s: owner %d:%d %s:%s, want root", h.Name, h.Uid, h.Gid, h.Uname, h.Gname)
		}
		if !h.ModTime.Equal(testEpoch) {
			t.Errorf("%s: time %v, want the epoch", h.Name, h.ModTime)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name] = tarFile{Header: h, Data: string(b)}
		order = append(order, h.Name)
	}
	return files, order
}

func buildSample(t *testing.T) ([]Package, string) {
	t.Helper()
	dir := workdir(t)
	pkgs, err := Build(sampleManifest(dir), testEpoch, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return pkgs, dir
}

// A manifest yields one package per architecture whose files resolve the
// placeholders per architecture.
func TestBuildFromManifest(t *testing.T) {
	pkgs, dir := buildSample(t)
	if len(pkgs) != 2 || pkgs[0].Arch != "amd64" || pkgs[1].Arch != "arm64" {
		t.Fatalf("packages = %+v", pkgs)
	}
	if pkgs[0].FileName != "hello_2.10.0~rc1-1_amd64.deb" {
		t.Errorf("file name = %s", pkgs[0].FileName)
	}
	for _, p := range pkgs {
		v := parseLikeDpkg(t, p.Data)
		want, _ := os.ReadFile(filepath.Join(dir, "downloads", "hello_linux_"+p.Arch))
		if v.Data["./usr/bin/hello"].Data != string(want) {
			t.Errorf("%s: /usr/bin/hello is not the %s program", p.Arch, p.Arch)
		}
		uname := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[p.Arch]
		want, _ = os.ReadFile(filepath.Join(dir, "downloads", "hello-"+uname))
		if v.Data["./usr/libexec/hello/hello-uname"].Data != string(want) {
			t.Errorf("%s: {uname} not resolved to %s", p.Arch, uname)
		}
	}
	spec.Verified(t, reqpkg.RPkgBuildFromFiles)
}

// The placeholders {arch} and {uname} are replaced per architecture.
func TestArchPlaceholders(t *testing.T) {
	for _, a := range []string{"amd64", "arm64", "armhf", "i386", "riscv64", "ppc64el", "s390x"} {
		got := expand("bin/{arch}/tool-{uname}", mustArch(t, a))
		uname := map[string]string{"amd64": "x86_64", "arm64": "aarch64", "armhf": "armv7l", "i386": "i686", "riscv64": "riscv64", "ppc64el": "ppc64le", "s390x": "s390x"}[a]
		if got != "bin/"+a+"/tool-"+uname {
			t.Errorf("%s: %s", a, got)
		}
	}
	spec.Verified(t, reqpkg.RPkgBuildFromFiles)
}

// The package is laid out the way dpkg reads it: ar headers, order, tar
// with "./", root, timestamp, directories before their contents, sorted,
// modes, symlinks and directory trees.
func TestParseLikeDpkg(t *testing.T) {
	pkgs, _ := buildSample(t)
	v := parseLikeDpkg(t, pkgs[0].Data)
	if v.Order[0] != "./" {
		t.Errorf("first data entry = %q", v.Order[0])
	}
	for i := 1; i < len(v.Order); i++ {
		if v.Order[i-1] >= v.Order[i] {
			t.Errorf("data entries not sorted: %q before %q", v.Order[i-1], v.Order[i])
		}
	}
	for _, tc := range []struct {
		name string
		typ  byte
		mode int64
	}{
		{"./usr/", tar.TypeDir, 0o755},
		{"./usr/bin/hello", tar.TypeReg, 0o755},
		{"./usr/libexec/hello/hello-uname", tar.TypeReg, 0o755},
		{"./usr/lib/systemd/system/hello.service", tar.TypeReg, 0o644},
		{"./etc/hello/hello.conf", tar.TypeReg, 0o640},
		{"./var/lib/hello/", tar.TypeDir, 0o750},
		{"./usr/share/hello/", tar.TypeDir, 0o755},
		{"./usr/share/hello/doc/README", tar.TypeReg, 0o644},
		{"./usr/share/hello/bin/tool", tar.TypeReg, 0o755},
		{"./usr/sbin/hello", tar.TypeSymlink, 0o777},
	} {
		f, ok := v.Data[tc.name]
		if !ok {
			t.Errorf("%s missing", tc.name)
			continue
		}
		if f.Header.Typeflag != tc.typ || f.Header.Mode != tc.mode {
			t.Errorf("%s: type %c mode %o, want %c %o", tc.name, f.Header.Typeflag, f.Header.Mode, tc.typ, tc.mode)
		}
	}
	if l := v.Data["./usr/sbin/hello"].Header.Linkname; l != "/usr/bin/hello" {
		t.Errorf("symlink target %q", l)
	}
	spec.Verified(t, reqpkg.RPkgBuildFromFiles, reqpkg.RPkgControlData)
}

// The control file carries all fields in the order Debian expects, with a
// wrapped description and the correct Installed-Size.
func TestControlFields(t *testing.T) {
	pkgs, _ := buildSample(t)
	v := parseLikeDpkg(t, pkgs[0].Data)
	control := v.Control["./control"].Data
	var keys []string
	for line := range strings.SplitSeq(strings.TrimSuffix(control, "\n"), "\n") {
		if len(line) > 80 {
			t.Errorf("control line longer than 80 characters: %q", line)
		}
		if !strings.HasPrefix(line, " ") {
			k, _, _ := strings.Cut(line, ":")
			keys = append(keys, k)
		}
	}
	want := "Package Version Architecture Maintainer Installed-Size Depends Recommends Section Priority Homepage X-Origin-URL Description"
	if strings.Join(keys, " ") != want {
		t.Errorf("fields = %v, want %s", keys, want)
	}
	for _, line := range []string{
		"Package: hello\n", "Version: 1:2.10.0~rc1-1\n", "Architecture: amd64\n",
		"Maintainer: worldiety GmbH <support@worldiety.de>\n",
		"Depends: libc6 (>= 2.34), adduser | passwd\n", "Section: utils\n", "Priority: optional\n",
		"Description: Says hello\n Hello greets the world.", "\n .\n Second paragraph.\n .\n   hello --loud\n   hello --quiet\n",
	} {
		if !strings.Contains(control, line) {
			t.Errorf("control lacks %q:\n%s", line, control)
		}
	}
	// 1 KiB per entry, plus the rounded-up size of each file.
	size := int64(0)
	for name, f := range v.Data {
		if name == "./" {
			continue
		}
		size++
		if f.Header.Typeflag == tar.TypeReg {
			size += (f.Header.Size + 1023) / 1024
		}
	}
	if !strings.Contains(control, fmt.Sprintf("Installed-Size: %d\n", size)) {
		t.Errorf("Installed-Size is not %d:\n%s", size, control)
	}
	spec.Verified(t, reqpkg.RPkgControlData)
}

// md5sums names every file except conffiles, conffiles names the
// conffiles, and the maintainer scripts lie executable in control.tar.
func TestConffilesAndScripts(t *testing.T) {
	pkgs, dir := buildSample(t)
	v := parseLikeDpkg(t, pkgs[0].Data)
	if got := v.Control["./conffiles"].Data; got != "/etc/hello/hello.conf\n" {
		t.Errorf("conffiles = %q", got)
	}
	sums := v.Control["./md5sums"].Data
	for name, f := range v.Data {
		if f.Header.Typeflag != tar.TypeReg {
			continue
		}
		line := fmt.Sprintf("%x  %s\n", md5.Sum([]byte(f.Data)), strings.TrimPrefix(name, "./"))
		if has := strings.Contains(sums, line); has == (name == "./etc/hello/hello.conf") {
			t.Errorf("md5sums and %s: %v\n%s", name, has, sums)
		}
	}
	for _, s := range []string{"postinst", "prerm"} {
		f, ok := v.Control["./"+s]
		want, _ := os.ReadFile(filepath.Join(dir, "scripts", s))
		if !ok || f.Data != string(want) || f.Header.Mode != 0o755 {
			t.Errorf("%s: %v %o", s, ok, f.Header.Mode)
		}
	}
	if _, ok := v.Control["./preinst"]; ok {
		t.Error("preinst without a script")
	}
	spec.Verified(t, reqpkg.RPkgControlData)
}

// Equal inputs and an equal timestamp yield the same bytes, a different
// timestamp different ones.
func TestDebIsReproducible(t *testing.T) {
	dir := workdir(t)
	a, err := Build(sampleManifest(dir), testEpoch, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(sampleManifest(dir), testEpoch, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Build(sampleManifest(dir), testEpoch.Add(time.Second), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if !bytes.Equal(a[i].Data, b[i].Data) {
			t.Errorf("%s: two builds differ", a[i].FileName)
		}
		if bytes.Equal(a[i].Data, c[i].Data) {
			t.Errorf("%s: another epoch gives the same bytes", a[i].FileName)
		}
	}
	spec.Verified(t, nfr.RNfrReproducibility)
}

// WriteFile stores the package; the same package again is nothing to do, a
// different one under the same name is an error.
func TestWriteFileNeverReplaces(t *testing.T) {
	pkgs, _ := buildSample(t)
	out := t.TempDir()
	name, unchanged, err := WriteFile(out, pkgs[0])
	if err != nil || unchanged {
		t.Fatalf("first write: %v %v", unchanged, err)
	}
	if _, unchanged, err = WriteFile(out, pkgs[0]); err != nil || !unchanged {
		t.Fatalf("second write: %v %v", unchanged, err)
	}
	other := pkgs[0]
	other.Data = append([]byte(nil), other.Data...)
	other.Data[len(other.Data)-1] ^= 1
	if _, _, err = WriteFile(out, other); err == nil {
		t.Fatal("different content replaced the package")
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 1 || filepath.Join(out, entries[0].Name()) != name {
		t.Errorf("files left: %v", entries)
	}
}

// Invalid inputs are all reported at once, and nothing is created.
func TestRejectsInvalidInput(t *testing.T) {
	dir := workdir(t)
	m := &Manifest{
		Package:       "Hello_World",
		Version:       "v1.0",
		Architectures: []string{"x86_64", "amd64", "amd64"},
		Maintainer:    "nobody",
		Summary:       "",
		Depends:       []string{"libc6 (>> )"},
		Files: []File{
			{Src: "hello.service", Dst: "usr/lib/hello.service"},
			{Src: "hello.service", Dst: "/usr/../etc/x"},
			{Src: "hello.service", Dst: "/"},
			{Src: "hello.service", Dst: "/usr/bin/a", Mode: "4755"},
			{Src: "hello.service", Dst: "/usr/bin/b", Mode: "rwx"},
			{Src: "hello.service", Dst: "/usr/bin/c"},
			{Src: "missing", Dst: "/usr/bin/d"},
			{Src: "hello.service", Dst: "/usr/bin/c/e"},
		},
		Directories: []Directory{{Path: "/usr/bin/c"}},
		Conffiles:   []string{"/etc/missing.conf"},
		Scripts:     Scripts{Postinst: "hello.conf"},
		Fields:      map[string]string{"Version": "2", "Bad Key": "x"},
		Dir:         dir,
	}
	_, err := Build(m, testEpoch, Options{})
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{
		`invalid package name "Hello_World"`,
		`invalid version "v1.0"`,
		`unknown architecture "x86_64"`,
		"architecture amd64 is given twice",
		`invalid maintainer "nobody"`,
		"the summary is missing",
		`invalid depends entry "libc6 (>> )"`,
		`file "usr/lib/hello.service": the target path must be absolute`,
		`file "/usr/../etc/x": the target path must be clean`,
		`file "/": the target path must not be the root`,
		"setuid, setgid and sticky bits are not allowed",
		`invalid mode "rwx"`,
		`directory "/usr/bin/c" is already a file of the package`,
		`file "/usr/bin/d" (amd64)`,
		`"/usr/bin/c/e" lies below "/usr/bin/c"`,
		`conffile "/etc/missing.conf" is no regular file`,
		`postinst script hello.conf does not start with "#!"`,
		"the field Version is set by wdyapt",
		`invalid field name "Bad Key"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
	if err := Validate(m, Options{}); err == nil {
		t.Error("Validate accepts what Build rejects")
	}
	spec.Verified(t, reqpkg.RPkgValidateInput)
}

// An ELF program must fit the architecture; "all" must not contain one;
// --no-arch-check turns this off; a dynamically linked program without
// Depends yields a warning.
func TestElfArchitectureCheck(t *testing.T) {
	dir := workdir(t)
	m := sampleManifest(dir)
	m.Files, m.Conffiles = []File{{Src: "downloads/hello_linux_amd64", Dst: "/usr/bin/hello"}}, nil
	err := Validate(m, Options{})
	if err == nil || !strings.Contains(err.Error(), "/usr/bin/hello is an ELF program for amd64") || !strings.Contains(err.Error(), "not for arm64") {
		t.Errorf("arm64 with an amd64 program: %v", err)
	}
	if err := Validate(m, Options{NoArchCheck: true}); err != nil {
		t.Errorf("--no-arch-check: %v", err)
	}
	m.Architectures = []string{"all"}
	if err := Validate(m, Options{}); err == nil || !strings.Contains(err.Error(), "architecture all must not contain ELF programs") {
		t.Errorf("all with a program: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "dyn"), fakeELF(t, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2"), 0o755); err != nil {
		t.Fatal(err)
	}
	m = sampleManifest(dir)
	m.Architectures, m.Depends = []string{"amd64"}, nil
	m.Files, m.Conffiles = []File{{Src: "dyn", Dst: "/usr/bin/dyn"}}, nil
	var warnings []string
	if err := Validate(m, Options{Warn: func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) }}); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "dynamically linked") {
		t.Errorf("warnings = %q", warnings)
	}
	spec.Verified(t, reqpkg.RPkgValidateInput)
}

// A manifest with an unknown field is rejected; relative sources are
// resolved from the directory of the manifest.
func TestManifestIsStrict(t *testing.T) {
	if _, err := ParseManifest([]byte(`{"package": "x", "colour": "red"}`)); err == nil || !strings.Contains(err.Error(), "colour") {
		t.Errorf("unknown field: %v", err)
	}
	dir := workdir(t)
	name := filepath.Join(dir, "hello.json")
	if err := os.WriteFile(name, []byte(`{
  "package": "hello", "version": "1.0-1", "architectures": ["amd64"],
  "maintainer": "A B <a@example.com>", "summary": "Says hello",
  "files": [{"src": "downloads/hello_linux_{arch}", "dst": "/usr/bin/hello", "mode": "0755"}],
  "scripts": {"postinst": "scripts/postinst"},
  "fields": {"X-Test": "yes"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(m, testEpoch, Options{}); err != nil {
		t.Fatal(err)
	}
	spec.Verified(t, reqpkg.RPkgBuildFromFiles)
}

// Read shows the control file, conffiles, scripts, files and checksums of a
// built package.
func TestInfoShowsPackage(t *testing.T) {
	pkgs, _ := buildSample(t)
	info, err := ReadBytes(pkgs[0].Data, true)
	if err != nil {
		t.Fatal(err)
	}
	size, sum := pkgs[0].Sum()
	if info.Size != size || info.SHA256 != sum || info.MD5 == "" {
		t.Errorf("size %d sha %s md5 %s", info.Size, info.SHA256, info.MD5)
	}
	if info.Name() != "hello" || info.Version() != "1:2.10.0~rc1-1" || info.Arch() != "amd64" {
		t.Errorf("control = %v", info.Control)
	}
	if strings.Join(info.Conffiles, " ") != "/etc/hello/hello.conf" || strings.Join(info.Scripts, " ") != "postinst prerm" {
		t.Errorf("conffiles %v scripts %v", info.Conffiles, info.Scripts)
	}
	if info.PoolPath("main") != "pool/main/h/hello/hello_2.10.0~rc1-1_amd64.deb" {
		t.Errorf("pool path %s", info.PoolPath("main"))
	}
	found := false
	for _, f := range info.Files {
		if f.Path == "./usr/sbin/hello" && f.Type == "symlink" && f.Link == "/usr/bin/hello" {
			found = true
		}
	}
	if !found {
		t.Errorf("files = %+v", info.Files)
	}
	spec.Verified(t, reqpkg.RPkgShow)
}

// Foreign packages: ar names with "/", control.tar without compression,
// data.tar.xz without a file list; control.tar.xz is rejected with an
// explanation.
func TestReadsForeignPackages(t *testing.T) {
	control := []entry{{Name: "control", Mode: 0o644, Data: []byte("Package: foreign\nVersion: 1.0\nArchitecture: mips64el\nSource: foreign-src (1.0)\nDescription: x\n")}}
	var plainTar bytes.Buffer
	tw := tar.NewWriter(&plainTar)
	for _, e := range control {
		tw.WriteHeader(&tar.Header{Name: "./" + e.Name, Mode: e.Mode, Size: int64(len(e.Data)), Typeflag: tar.TypeReg})
		tw.Write(e.Data)
	}
	tw.Close()
	var deb bytes.Buffer
	writeArSlash := func(members []member) {
		deb.Reset()
		deb.WriteString("!<arch>\n")
		for _, m := range members {
			fmt.Fprintf(&deb, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m.Name+"/", 0, 0, 0, "100644", len(m.Data))
			deb.Write(m.Data)
			if len(m.Data)%2 == 1 {
				deb.WriteByte('\n')
			}
		}
	}
	writeArSlash([]member{{"debian-binary", []byte("2.0\n")}, {"control.tar", plainTar.Bytes()}, {"data.tar.xz", []byte("xz data")}})
	info, err := ReadBytes(deb.Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name() != "foreign" || info.Files != nil || !strings.Contains(info.FilesNote, "xz") {
		t.Errorf("info = %+v", info)
	}
	if info.PoolPath("main") != "pool/main/f/foreign-src/foreign_1.0_mips64el.deb" {
		t.Errorf("pool path %s", info.PoolPath("main"))
	}
	writeArSlash([]member{{"debian-binary", []byte("2.0\n")}, {"control.tar.xz", []byte("x")}, {"data.tar.xz", []byte("x")}})
	if _, err := ReadBytes(deb.Bytes(), false); err == nil || !strings.Contains(err.Error(), "dpkg-deb -Zgzip") {
		t.Errorf("control.tar.xz: %v", err)
	}
	if _, err := ReadBytes([]byte("hello"), false); err == nil {
		t.Error("not an ar archive accepted")
	}
	spec.Verified(t, reqpkg.RPkgShow)
}

func mustArch(t *testing.T, name string) debian.Arch {
	t.Helper()
	a, ok := debian.LookupArch(name)
	if !ok {
		t.Fatalf("no arch %s", name)
	}
	return a
}
