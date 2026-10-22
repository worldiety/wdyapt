package deb

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/debian"
)

// Package is a built package.
type Package struct {
	Name    string
	Version string
	Arch    string
	// FileName is <name>_<version without epoch>_<arch>.deb.
	FileName string
	Data     []byte
}

// Build builds one Debian binary package per architecture from m, the way
// dpkg accepts it: ar with debian-binary, control.tar.gz and data.tar.gz.
// All timestamps are epoch, all files belong to root, the entries are
// sorted and gzip carries neither name nor time; the same inputs yield the
// same bytes with the same Go version
// (R-PKG-BUILD-FROM-FILES, R-PKG-CONTROL-DATA, R-NFR-REPRODUCIBILITY).
// It checks everything with Validate first; on any defect no package is
// built.
func Build(m *Manifest, epoch time.Time, opts Options) ([]Package, error) {
	plans, err := prepare(m, opts)
	if err != nil {
		return nil, err
	}
	epoch = time.Unix(epoch.Unix(), 0).UTC()
	var out []Package
	for _, p := range plans {
		data := tree(p.data)
		var sums strings.Builder
		size := int64(0)
		for _, e := range data {
			size++
			if e.dir() || e.link() {
				continue
			}
			size += (int64(len(e.Data)) + 1023) / 1024
			if !slices.Contains(p.conffiles, "/"+e.Name) {
				fmt.Fprintf(&sums, "%x  %s\n", md5.Sum(e.Data), e.Name)
			}
		}
		control := []entry{{Name: "control", Mode: 0o644, Data: []byte(controlFile(m, p, size).String())}}
		if sums.Len() > 0 {
			control = append(control, entry{Name: "md5sums", Mode: 0o644, Data: []byte(sums.String())})
		}
		if len(p.conffiles) > 0 {
			control = append(control, entry{Name: "conffiles", Mode: 0o644, Data: []byte(strings.Join(p.conffiles, "\n") + "\n")})
		}
		for _, s := range p.scripts {
			control = append(control, entry{Name: s.Name, Mode: 0o755, Data: s.Data})
		}
		slices.SortFunc(control, func(a, b entry) int { return strings.Compare(a.Name, b.Name) })
		controlTar, err := tarGz(control, epoch)
		if err != nil {
			return nil, err
		}
		dataTar, err := tarGz(data, epoch)
		if err != nil {
			return nil, err
		}
		var deb bytes.Buffer
		err = writeAr(&deb, []member{
			{Name: "debian-binary", Data: []byte("2.0\n")},
			{Name: "control.tar.gz", Data: controlTar},
			{Name: "data.tar.gz", Data: dataTar},
		}, epoch)
		if err != nil {
			return nil, err
		}
		out = append(out, Package{
			Name:     m.Package,
			Version:  m.Version,
			Arch:     p.arch.Name,
			FileName: FileName(m.Package, p.version, p.arch.Name),
			Data:     deb.Bytes(),
		})
	}
	return out, nil
}

// FileName is the usual file name of a package: name, version without
// epoch, and architecture.
func FileName(name string, v debian.Version, arch string) string {
	return fmt.Sprintf("%s_%s_%s.deb", name, v.WithoutEpoch(), arch)
}

// controlFile is the control file of the package; size is the size of the
// installed files in KiB.
func controlFile(m *Manifest, p archPlan, size int64) debian.Paragraph {
	c := debian.Paragraph{
		{Key: "Package", Value: m.Package},
		{Key: "Version", Value: m.Version},
		{Key: "Architecture", Value: p.arch.Name},
		{Key: "Maintainer", Value: m.Maintainer},
		{Key: "Installed-Size", Value: strconv.FormatInt(size, 10)},
	}
	for _, r := range relations(m) {
		if len(r.items) > 0 {
			c = append(c, debian.Field{Key: r.field, Value: strings.Join(r.items, ", ")})
		}
	}
	c = append(c, debian.Field{Key: "Section", Value: or(m.Section, "misc")}, debian.Field{Key: "Priority", Value: or(m.Priority, "optional")})
	if m.Homepage != "" {
		c = append(c, debian.Field{Key: "Homepage", Value: m.Homepage})
	}
	for _, k := range sortedKeys(m.Fields) {
		c = append(c, debian.Field{Key: k, Value: m.Fields[k]})
	}
	return append(c, debian.Field{Key: "Description", Value: description(m.Summary, m.Description)})
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// description forms the field Description: the summary on the first line,
// then the paragraphs wrapped at 72 characters and indented by one space,
// blank lines as " .". A paragraph whose lines start with a space stays
// verbatim, as Debian intends for examples.
func description(summary, long string) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(summary))
	paragraphs := strings.Split(strings.Trim(long, "\n"), "\n\n")
	first := true
	for _, para := range paragraphs {
		if strings.TrimSpace(para) == "" {
			continue
		}
		if !first {
			b.WriteString("\n .")
		}
		first = false
		if strings.HasPrefix(para, " ") {
			for line := range strings.SplitSeq(para, "\n") {
				b.WriteString("\n " + strings.TrimRight(line, " \t"))
			}
			continue
		}
		for _, line := range wrap(para, 72) {
			b.WriteString("\n " + line)
		}
	}
	return b.String()
}

// wrap breaks text at spaces into lines of at most width characters.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) > width:
			lines = append(lines, line)
			line = word
		default:
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// ErrDifferentFile reports an existing target file with different contents.
var ErrDifferentFile = errors.New("a different file of that name exists")

// WriteFile writes the package to dir: first under a temporary name, then
// renamed. If the file already exists with the same contents, it stays and
// unchanged is true; with different contents that is an error.
func WriteFile(dir string, p Package) (name string, unchanged bool, err error) {
	name = filepath.Join(dir, p.FileName)
	if old, err := os.ReadFile(name); err == nil {
		if bytes.Equal(old, p.Data) {
			return name, true, nil
		}
		return name, false, fmt.Errorf("%s: %w; remove it or build another version", name, ErrDifferentFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return name, false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return name, false, err
	}
	tmp, err := os.CreateTemp(dir, "."+p.FileName+".*.tmp")
	if err != nil {
		return name, false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(p.Data); err != nil {
		tmp.Close()
		return name, false, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return name, false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return name, false, err
	}
	if err := tmp.Close(); err != nil {
		return name, false, err
	}
	return name, false, os.Rename(tmp.Name(), name)
}

// Sum is the size and SHA256 of a package as it would lie in the pool.
func (p Package) Sum() (int64, string) {
	h := sha256.Sum256(p.Data)
	return int64(len(p.Data)), hex.EncodeToString(h[:])
}
