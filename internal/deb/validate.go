package deb

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/worldiety/wdyapt/internal/debian"
)

// Options controls checking and building.
type Options struct {
	// NoArchCheck turns off the check whether ELF programs fit the
	// architecture.
	NoArchCheck bool
	// Warn receives notes that do not prevent the build, such as a
	// dynamically linked program without Depends. May be nil.
	Warn func(format string, args ...any)
}

func (o Options) warn(format string, args ...any) {
	if o.Warn != nil {
		o.Warn(format, args...)
	}
}

var (
	maintainerPattern = regexp.MustCompile(`^[^<>\n]*[^<>\s] <[^<>@\s]+@[^<>\s]+>$`)
	fieldKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	relationPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+(:[a-z0-9-]+)?( *\( *(<<|<=|=|>=|>>) *[A-Za-z0-9.+~:-]+ *\))?( *\[[^\]\n]*\])?( *<[^>\n]*>)*$`)
)

// managedFields are set by wdyapt itself; --field must not set them.
var managedFields = []string{
	"Package", "Version", "Architecture", "Maintainer", "Installed-Size", "Description",
	"Depends", "Pre-Depends", "Recommends", "Suggests", "Conflicts", "Breaks", "Replaces", "Provides",
	"Section", "Priority", "Homepage", "Filename", "Size", "MD5sum", "SHA256", "SHA1", "Status",
}

// archPlan is everything that has been read and checked for the package of
// one architecture.
type archPlan struct {
	arch      debian.Arch
	version   debian.Version
	data      []entry
	conffiles []string
	scripts   []member
}

// Validate checks a manifest completely before anything is built: name,
// version, architectures, maintainer, description, relations, target paths,
// modes, conffiles, maintainer scripts and further fields, plus per
// architecture all source files and whether ELF programs fit the
// architecture. It reports all defects at once (R-PKG-VALIDATE-INPUT).
func Validate(m *Manifest, opts Options) error {
	_, err := prepare(m, opts)
	return err
}

// prepare checks m and reads all sources; only when there is nothing to
// object to does it return the plans per architecture.
func prepare(m *Manifest, opts Options) ([]archPlan, error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if m.Package == "" {
		fail("the package name is missing (--name or \"package\")")
	} else if err := debian.ValidName(m.Package); err != nil {
		fail("%v", err)
	}
	var version debian.Version
	if m.Version == "" {
		fail("the version is missing (--version or \"version\")")
	} else if v, err := debian.ParseVersion(m.Version); err != nil {
		fail("%v", err)
	} else {
		version = v
	}
	var arches []debian.Arch
	if len(m.Architectures) == 0 {
		fail("no architecture given (--arch or \"architectures\")")
	}
	for _, name := range m.Architectures {
		a, ok := debian.LookupArch(name)
		if !ok {
			fail("%v", debian.ValidArch(name))
			continue
		}
		if slices.ContainsFunc(arches, func(b debian.Arch) bool { return b.Name == a.Name }) {
			fail("architecture %s is given twice", name)
			continue
		}
		arches = append(arches, a)
	}
	if slices.ContainsFunc(arches, func(a debian.Arch) bool { return a.Name == "all" }) && len(arches) > 1 {
		fail("architecture all cannot be combined with other architectures")
	}
	switch {
	case m.Maintainer == "":
		fail("the maintainer is missing (--maintainer, WDYAPT_MAINTAINER or \"maintainer\")")
	case !maintainerPattern.MatchString(m.Maintainer):
		fail("invalid maintainer %q: use \"Name <mail@example.com>\"", m.Maintainer)
	}
	switch {
	case strings.TrimSpace(m.Summary) == "":
		fail("the summary is missing (--summary or \"summary\")")
	case strings.ContainsAny(m.Summary, "\n\r"):
		fail("the summary must be one line")
	case len(m.Summary) > 80:
		fail("the summary has %d characters; keep it below 80", len(m.Summary))
	}
	if strings.Contains(m.Description, "\r") {
		fail("the description contains a carriage return")
	}
	for _, f := range []struct{ name, value string }{{"homepage", m.Homepage}, {"section", m.Section}, {"priority", m.Priority}} {
		if strings.ContainsAny(f.value, " \t\n\r") {
			fail("invalid %s %q", f.name, f.value)
		}
	}
	for _, rel := range relations(m) {
		for _, item := range rel.items {
			for alt := range strings.SplitSeq(item, "|") {
				if !relationPattern.MatchString(strings.TrimSpace(alt)) {
					fail("invalid %s entry %q: use \"name\", \"name (>= 1.0)\" or alternatives with \"|\"", strings.ToLower(rel.field), item)
				}
			}
		}
	}
	for _, key := range sortedKeys(m.Fields) {
		switch {
		case !fieldKeyPattern.MatchString(key):
			fail("invalid field name %q", key)
		case slices.ContainsFunc(managedFields, func(f string) bool { return strings.EqualFold(f, key) }):
			fail("the field %s is set by wdyapt or by its own option, not by --field", key)
		case strings.TrimSpace(m.Fields[key]) == "" || strings.ContainsAny(m.Fields[key], "\n\r"):
			fail("the field %s needs a value on one line", key)
		}
	}
	if len(m.Files) == 0 && len(m.Directories) == 0 {
		fail("the package has no files and no directories (--file, --dir or \"files\")")
	}

	// Targets, modes and symlinks do not depend on the architecture.
	targets := map[string]string{} // target -> kind
	addTarget := func(dst, kind string) bool {
		if err := checkTarget(dst); err != nil {
			fail("%s %q: %v", kind, dst, err)
			return false
		}
		if other, ok := targets[dst]; ok {
			fail("%s %q is already a %s of the package", kind, dst, other)
			return false
		}
		targets[dst] = kind
		return true
	}
	fileModes := make([]int64, len(m.Files))
	for i, f := range m.Files {
		if f.Src == "" {
			fail("file %q has no source", f.Dst)
		}
		addTarget(f.Dst, "file")
		fileModes[i] = -1
		if f.Mode != "" {
			mode, err := parseMode(f.Mode)
			if err != nil {
				fail("file %q: %v", f.Dst, err)
			}
			fileModes[i] = mode
		}
	}
	dirModes := make([]int64, len(m.Directories))
	for i, d := range m.Directories {
		addTarget(d.Path, "directory")
		dirModes[i] = 0o755
		if d.Mode != "" {
			mode, err := parseMode(d.Mode)
			if err != nil {
				fail("directory %q: %v", d.Path, err)
			}
			dirModes[i] = mode
		}
	}
	for _, s := range m.Symlinks {
		addTarget(s.Path, "symlink")
		if s.Target == "" || strings.ContainsAny(s.Target, "\x00\n") {
			fail("symlink %q needs a target", s.Path)
		}
	}
	var scripts []member
	for _, s := range m.Scripts.list() {
		data, err := os.ReadFile(m.source(s[1]))
		if err != nil {
			fail("%s script: %v", s[0], err)
			continue
		}
		if !bytes.HasPrefix(data, []byte("#!")) {
			fail("%s script %s does not start with \"#!\"", s[0], s[1])
			continue
		}
		scripts = append(scripts, member{Name: s[0], Data: data})
	}

	var plans []archPlan
	for _, a := range arches {
		plan := archPlan{arch: a, version: version, scripts: scripts}
		names := map[string]bool{}
		add := func(e entry, kind, dst string) {
			if names[e.Name] {
				fail("%s %q: %s is already a part of the package", kind, dst, "/"+strings.TrimSuffix(e.Name, "/"))
				return
			}
			names[e.Name] = true
			plan.data = append(plan.data, e)
		}
		for i, f := range m.Files {
			if f.Src == "" || checkTarget(f.Dst) != nil {
				continue
			}
			src := m.source(expand(f.Src, a))
			if strings.HasSuffix(f.Src, "/") {
				entries, err := readTree(src, strings.TrimPrefix(f.Dst, "/"))
				if err != nil {
					fail("file %q (%s, %s): %v", f.Dst, a.Name, src, err)
					continue
				}
				for _, e := range entries {
					add(e, "file", f.Dst)
				}
				continue
			}
			info, err := os.Stat(src)
			if err != nil {
				fail("file %q (%s): %v", f.Dst, a.Name, err)
				continue
			}
			if !info.Mode().IsRegular() {
				fail("file %q (%s): %s is not a regular file; end the source with \"/\" to take a directory", f.Dst, a.Name, src)
				continue
			}
			data, err := os.ReadFile(src)
			if err != nil {
				fail("file %q (%s): %v", f.Dst, a.Name, err)
				continue
			}
			mode := fileModes[i]
			if mode < 0 {
				mode = defaultMode(info.Mode())
			}
			add(entry{Name: strings.TrimPrefix(f.Dst, "/"), Mode: mode, Data: data}, "file", f.Dst)
		}
		for i, d := range m.Directories {
			if checkTarget(d.Path) == nil {
				add(entry{Name: strings.TrimPrefix(d.Path, "/") + "/", Mode: dirModes[i]}, "directory", d.Path)
			}
		}
		for _, s := range m.Symlinks {
			if checkTarget(s.Path) == nil && s.Target != "" {
				add(entry{Name: strings.TrimPrefix(s.Path, "/"), Mode: 0o777, Target: s.Target}, "symlink", s.Path)
			}
		}
		// An entry must not lie below a file or a symlink.
		for _, e := range plan.data {
			for d := path.Dir(strings.TrimSuffix(e.Name, "/")); d != "."; d = path.Dir(d) {
				if names[d] {
					fail("%q lies below %q, which is a file or symlink", "/"+strings.TrimSuffix(e.Name, "/"), "/"+d)
				}
			}
		}
		for _, c := range m.Conffiles {
			name := strings.TrimPrefix(c, "/")
			i := slices.IndexFunc(plan.data, func(e entry) bool { return e.Name == name })
			switch {
			case !strings.HasPrefix(c, "/"):
				fail("conffile %q must be an absolute path", c)
			case i < 0 || plan.data[i].dir() || plan.data[i].link():
				fail("conffile %q is no regular file of the %s package", c, a.Name)
			default:
				if !strings.HasPrefix(c, "/etc/") {
					opts.warn("conffile %s is not below /etc", c)
				}
				if !slices.Contains(plan.conffiles, c) {
					plan.conffiles = append(plan.conffiles, c)
				}
			}
		}
		for _, e := range plan.data {
			if e.dir() || e.link() || !bytes.HasPrefix(e.Data, []byte("\x7fELF")) {
				continue
			}
			f, err := elf.NewFile(bytes.NewReader(e.Data))
			if err != nil {
				if !opts.NoArchCheck {
					fail("/%s (%s) starts like an ELF program but cannot be read: %v", e.Name, a.Name, err)
				}
				continue
			}
			if !opts.NoArchCheck {
				if err := a.MatchesELF(f.FileHeader); err != nil {
					fail("/%s %v (or use --no-arch-check)", e.Name, err)
					continue
				}
			}
			if len(m.Depends) == 0 && len(m.PreDepends) == 0 {
				if interp := interpreter(f); interp != "" {
					libs, _ := f.ImportedLibraries()
					if len(libs) > 0 {
						opts.warn("/%s (%s) is dynamically linked against %s, but the package has no Depends", e.Name, a.Name, strings.Join(libs, ", "))
					} else {
						opts.warn("/%s (%s) is dynamically linked (%s), but the package has no Depends", e.Name, a.Name, interp)
					}
				}
			}
		}
		plans = append(plans, plan)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return plans, nil
}

// checkTarget checks a target path in the package.
func checkTarget(dst string) error {
	switch {
	case dst == "":
		return errors.New("the target path is empty")
	case !strings.HasPrefix(dst, "/"):
		return errors.New("the target path must be absolute")
	case dst == "/":
		return errors.New("the target path must not be the root")
	case path.Clean(dst) != dst || slices.Contains(strings.Split(dst, "/"), ".."):
		return errors.New("the target path must be clean, without \"..\", \".\", \"//\" or a trailing \"/\"")
	case strings.ContainsAny(dst, "\x00\n\r"):
		return errors.New("the target path contains a control character")
	}
	return nil
}

// parseMode reads an octal mode 0000–0777; setuid, setgid and sticky are
// rejected.
func parseMode(s string) (int64, error) {
	mode, err := strconv.ParseInt(s, 8, 64)
	if err != nil || mode < 0 {
		return 0, fmt.Errorf("invalid mode %q: use octal digits such as 0644 or 0755", s)
	}
	if mode > 0o777 {
		return 0, fmt.Errorf("mode %s: setuid, setgid and sticky bits are not allowed", s)
	}
	return mode, nil
}

// defaultMode is 0755 if the source has an x bit, otherwise 0644.
func defaultMode(m fs.FileMode) int64 {
	if m&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

// expand replaces the placeholders {arch} and {uname} in a source.
func expand(src string, a debian.Arch) string {
	return strings.NewReplacer("{arch}", a.Name, "{uname}", a.Uname).Replace(src)
}

// readTree reads a source directory recursively as entries below dst.
// Modes are normalized; symbolic links in the source tree are an error
// because it would be unclear whether their target or the link is meant.
func readTree(src, dst string) ([]entry, error) {
	info, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory")
	}
	var out []entry
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		name := path.Join(dst, filepath.ToSlash(rel))
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("%s is a symbolic link; use --symlink for links", p)
		case d.IsDir():
			out = append(out, entry{Name: name + "/", Mode: 0o755})
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out = append(out, entry{Name: name, Mode: defaultMode(info.Mode()), Data: data})
		default:
			return fmt.Errorf("%s is neither a file nor a directory", p)
		}
		return nil
	})
	return out, err
}

// interpreter returns the program interpreter of a dynamically linked
// program, empty for a static one.
func interpreter(f *elf.File) string {
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b := make([]byte, p.Filesz)
			if _, err := p.ReadAt(b, 0); err != nil {
				return "unknown interpreter"
			}
			return strings.TrimRight(string(b), "\x00")
		}
	}
	return ""
}

// relation is a relationship field of the package.
type relation struct {
	field string
	items []string
}

// relations returns the relationship fields in the order of the control
// file.
func relations(m *Manifest) []relation {
	return []relation{
		{"Pre-Depends", m.PreDepends}, {"Depends", m.Depends}, {"Recommends", m.Recommends},
		{"Suggests", m.Suggests}, {"Conflicts", m.Conflicts}, {"Breaks", m.Breaks},
		{"Replaces", m.Replaces}, {"Provides", m.Provides},
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
