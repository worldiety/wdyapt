package debian

import (
	"debug/elf"
	"strings"
	"testing"
)

func TestParseKeepsOrderAndContinuationLines(t *testing.T) {
	text := "Origin: worldiety\nLabel: worldiety Hub\nSHA256:\n abc 12 main/binary-amd64/Packages\n def 34 main/binary-arm64/Packages\nDescription: short\n long line\n .\n more\n\nPackage: b\n"
	ps, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("%d paragraphs", len(ps))
	}
	if got := ps[0].Get("sha256"); got != "\n abc 12 main/binary-amd64/Packages\n def 34 main/binary-arm64/Packages" {
		t.Errorf("SHA256 = %q", got)
	}
	if got := Lines(ps[0].Get("SHA256")); len(got) != 2 || got[1] != "def 34 main/binary-arm64/Packages" {
		t.Errorf("Lines = %q", got)
	}
	if got := Format(ps); got != text {
		t.Errorf("round trip:\n%s\nwant:\n%s", got, text)
	}
}

func TestParseRejectsBrokenText(t *testing.T) {
	for _, text := range []string{" leading continuation\n", "no colon\n", "Bad Key: x\n", "A: 1\nA: 2\n"} {
		if _, err := Parse(text); err == nil {
			t.Errorf("%q: no error", text)
		}
	}
	if _, err := ParseOne("A: 1\n\nB: 2\n"); err == nil {
		t.Error("two paragraphs accepted as one")
	}
}

func TestParagraphEditing(t *testing.T) {
	p := Paragraph{{"Package", "a"}, {"Version", "1"}, {"Description", "x"}}
	p = p.Insert("Description", Field{"Filename", "pool/a.deb"})
	p = p.Set("version", "2").Set("Size", "3").Delete("Package")
	if got := p.String(); got != "Version: 2\nFilename: pool/a.deb\nDescription: x\nSize: 3\n" {
		t.Errorf("got %q", got)
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"caddy", "wdyhub-runner", "libc6", "g++", "a.b", "0ad"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "Caddy", "-a", "a_b", "a b", "a/b", "../x"} {
		if err := ValidName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		in        string
		epoch     int
		up, rev   string
		noEpochFn string
	}{
		{"1.0", 0, "1.0", "", "1.0"},
		{"2.10.0-1", 0, "2.10.0", "1", "2.10.0-1"},
		{"1:2.0~rc1-3", 1, "2.0~rc1", "3", "2.0~rc1-3"},
		{"1.2-3-4", 0, "1.2-3", "4", "1.2-3-4"},
		{"2:1:2-1", 2, "1:2", "1", "1:2-1"},
		{"1.0~dev.20260101120000.aaaaaaaa", 0, "1.0~dev.20260101120000.aaaaaaaa", "", "1.0~dev.20260101120000.aaaaaaaa"},
	} {
		v, err := ParseVersion(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if v.Epoch != tc.epoch || v.Upstream != tc.up || v.Revision != tc.rev || v.WithoutEpoch() != tc.noEpochFn || v.String() != tc.in {
			t.Errorf("%q = %+v", tc.in, v)
		}
	}
	for _, bad := range []string{"", "a1.0", "1.0-", "1.0-a_b", "1:", "x:1.0", "1.0 1", "1.0/2", "1.0:2", "-1", "1.0_1", "1:a"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCompareVersionsLikeDpkg(t *testing.T) {
	order := []string{
		"0.9",
		"1.0~dev.20260101120000.aaaaaaaa",
		"1.0~dev.20260102120000.0000aaaa",
		"1.0",
		"1.0-1",
		"1.0-2",
		"1.0.1~rc1",
		"1.0.1",
		"1.9",
		"1.10",
		"1.10a",
		"1.10+b",
		"1:0.1",
	}
	for i := range order {
		for j := range order {
			got := CompareVersions(order[i], order[j])
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got != want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	if CompareVersions("1.01", "1.1") != 0 {
		t.Error("1.01 != 1.1")
	}
	if CompareVersions("1.0~~", "1.0~") >= 0 || CompareVersions("1.0~", "1.0") >= 0 {
		t.Error("~ does not sort before the end")
	}
}

func TestArches(t *testing.T) {
	for _, name := range []string{"amd64", "arm64", "armhf", "i386", "riscv64", "ppc64el", "s390x", "all"} {
		if err := ValidArch(name); err != nil {
			t.Error(err)
		}
	}
	if err := ValidArch("x86_64"); err == nil || !strings.Contains(err.Error(), "amd64") {
		t.Errorf("x86_64: %v", err)
	}
	amd64, _ := LookupArch("amd64")
	arm64, _ := LookupArch("arm64")
	s390x, _ := LookupArch("s390x")
	all, _ := LookupArch("all")
	amdHeader := elf.FileHeader{Class: elf.ELFCLASS64, Data: elf.ELFDATA2LSB, OSABI: elf.ELFOSABI_NONE, Machine: elf.EM_X86_64}
	if err := amd64.MatchesELF(amdHeader); err != nil {
		t.Error(err)
	}
	if err := arm64.MatchesELF(amdHeader); err == nil || !strings.Contains(err.Error(), "for amd64") {
		t.Errorf("arm64 accepts amd64: %v", err)
	}
	if err := all.MatchesELF(amdHeader); err == nil {
		t.Error("all accepts an ELF program")
	}
	if err := s390x.MatchesELF(elf.FileHeader{Class: elf.ELFCLASS64, Data: elf.ELFDATA2MSB, Machine: elf.EM_S390}); err != nil {
		t.Error(err)
	}
	freebsd := amdHeader
	freebsd.OSABI = elf.ELFOSABI_FREEBSD
	if err := amd64.MatchesELF(freebsd); err == nil {
		t.Error("amd64 accepts a FreeBSD program")
	}
	if amd64.Uname != "x86_64" || arm64.Uname != "aarch64" {
		t.Error("uname names")
	}
}
