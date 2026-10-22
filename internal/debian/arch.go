package debian

import (
	"debug/elf"
	"fmt"
	"slices"
	"strings"
)

// Arch is a Debian architecture that wdyapt knows.
type Arch struct {
	// Name is the Debian name, such as "amd64".
	Name string
	// Uname is the name "uname -m" reports on such machines.
	Uname string
	// Machine, Class and Order describe ELF programs of this architecture.
	Machine elf.Machine
	Class   elf.Class
	Order   string // "le" or "be"
}

// Arches are the architectures wdyapt builds packages for. "all" stands for
// packages without programs and has no ELF type.
var Arches = []Arch{
	{Name: "amd64", Uname: "x86_64", Machine: elf.EM_X86_64, Class: elf.ELFCLASS64, Order: "le"},
	{Name: "arm64", Uname: "aarch64", Machine: elf.EM_AARCH64, Class: elf.ELFCLASS64, Order: "le"},
	{Name: "armhf", Uname: "armv7l", Machine: elf.EM_ARM, Class: elf.ELFCLASS32, Order: "le"},
	{Name: "i386", Uname: "i686", Machine: elf.EM_386, Class: elf.ELFCLASS32, Order: "le"},
	{Name: "riscv64", Uname: "riscv64", Machine: elf.EM_RISCV, Class: elf.ELFCLASS64, Order: "le"},
	{Name: "ppc64el", Uname: "ppc64le", Machine: elf.EM_PPC64, Class: elf.ELFCLASS64, Order: "le"},
	{Name: "s390x", Uname: "s390x", Machine: elf.EM_S390, Class: elf.ELFCLASS64, Order: "be"},
	{Name: "all", Uname: "noarch"},
}

// LookupArch returns the architecture name.
func LookupArch(name string) (Arch, bool) {
	i := slices.IndexFunc(Arches, func(a Arch) bool { return a.Name == name })
	if i < 0 {
		return Arch{}, false
	}
	return Arches[i], true
}

// ValidArch checks whether wdyapt knows the architecture name.
func ValidArch(name string) error {
	if _, ok := LookupArch(name); !ok {
		names := make([]string, len(Arches))
		for i, a := range Arches {
			names[i] = a.Name
		}
		return fmt.Errorf("unknown architecture %q: use one of %s", name, strings.Join(names, ", "))
	}
	return nil
}

// ArchNamePattern checks an architecture name as it may appear in a foreign
// repository: lowercase letters, digits and "-".
func ArchNamePattern(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// MatchesELF checks whether an ELF header fits the architecture: machine,
// class, byte order and an OSABI for Linux (NONE or LINUX).
func (a Arch) MatchesELF(h elf.FileHeader) error {
	if a.Name == "all" {
		return fmt.Errorf("architecture all must not contain ELF programs; build the package per architecture")
	}
	order := "le"
	if h.Data == elf.ELFDATA2MSB {
		order = "be"
	}
	if h.Machine != a.Machine || h.Class != a.Class || order != a.Order {
		got := "unknown"
		for _, b := range Arches {
			if b.Machine == h.Machine && b.Class == h.Class && b.Order == order {
				got = b.Name
			}
		}
		return fmt.Errorf("is an ELF program for %s (%s, %s), not for %s", got, h.Machine, h.Class, a.Name)
	}
	if h.OSABI != elf.ELFOSABI_NONE && h.OSABI != elf.ELFOSABI_LINUX {
		return fmt.Errorf("is an ELF program for %s, not for Linux", h.OSABI)
	}
	return nil
}
