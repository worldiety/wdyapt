package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/worldiety/wdyapt/internal/debian"
)

// maxControlSize limits the unpacked control.tar; control files are small.
const maxControlSize = 16 << 20

// Info is what a package says about itself and what it looks like as a file.
type Info struct {
	Control   debian.Paragraph
	Conffiles []string
	// Scripts are the names of the maintainer scripts, sorted.
	Scripts []string
	// Files is the file list from data.tar; nil if it was not read or is not
	// readable (then FilesNote says why).
	Files     []FileInfo
	FilesNote string

	Size   int64
	MD5    string
	SHA256 string
}

// FileInfo is an entry from data.tar.
type FileInfo struct {
	Path string `json:"path"`
	Type string `json:"type"` // file, dir, symlink, hardlink, other
	Mode int64  `json:"mode"`
	Size int64  `json:"size"`
	Link string `json:"link,omitempty"`
}

// Name, Version and Arch return the fields of the control file.
func (i *Info) Name() string    { return i.Control.Get("Package") }
func (i *Info) Version() string { return i.Control.Get("Version") }
func (i *Info) Arch() string    { return i.Control.Get("Architecture") }

// FileName is the file name of the package in the pool.
func (i *Info) FileName() string {
	v, _ := debian.ParseVersion(i.Version())
	return FileName(i.Name(), v, i.Arch())
}

// PoolPath is the path of the package in the pool below the component
// component.
func (i *Info) PoolPath(component string) string {
	return debian.PoolPath(component, i.Name(), i.Control.Get("Source"), i.FileName())
}

// ReadFile reads the package in the file name; withFiles reads the file
// list too.
func ReadFile(name string, withFiles bool) (*Info, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := Read(f, withFiles)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return info, nil
}

// Read reads a Debian binary package from r: control file, conffiles,
// maintainer scripts and, with withFiles, the file list, plus size, MD5 and
// SHA256 of the whole file (R-PKG-SHOW). It accepts ar names with and
// without a trailing "/", control.tar.gz and control.tar; it rejects
// control.tar.xz and .zst with an explanation. The control file must be
// exactly one paragraph with a valid Package, Version and Architecture.
func Read(r io.Reader, withFiles bool) (*Info, error) {
	md5h, sha := md5.New(), sha256.New()
	counter := &byteCounter{}
	ar, err := newArReader(io.TeeReader(r, io.MultiWriter(md5h, sha, counter)))
	if err != nil {
		return nil, err
	}
	info := &Info{}
	seenControl, seenData := false, false
	for i := 0; ; i++ {
		name, _, body, err := ar.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch {
		case i == 0:
			if name != "debian-binary" {
				return nil, fmt.Errorf("not a Debian package: the first member is %q, not debian-binary", name)
			}
			b, err := io.ReadAll(io.LimitReader(body, 64))
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(string(b), "2.") {
				return nil, fmt.Errorf("unsupported Debian package format %q", strings.TrimSpace(string(b)))
			}
		case strings.HasPrefix(name, "control.tar"):
			if seenControl {
				return nil, fmt.Errorf("the package has two control archives")
			}
			seenControl = true
			if err := info.readControl(name, body); err != nil {
				return nil, err
			}
		case strings.HasPrefix(name, "data.tar"):
			seenData = true
			if withFiles {
				info.readData(name, body)
			}
		}
	}
	if !seenControl {
		return nil, fmt.Errorf("not a Debian package: control.tar is missing")
	}
	if !seenData {
		return nil, fmt.Errorf("not a Debian package: data.tar is missing")
	}
	info.Size = counter.n
	info.MD5 = hex.EncodeToString(md5h.Sum(nil))
	info.SHA256 = hex.EncodeToString(sha.Sum(nil))
	return info, nil
}

type byteCounter struct{ n int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// readControl reads control.tar.gz or control.tar.
func (i *Info) readControl(name string, body io.Reader) error {
	var r io.Reader
	switch name {
	case "control.tar.gz":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		r = zr
	case "control.tar":
		r = body
	case "control.tar.xz", "control.tar.zst":
		return fmt.Errorf("%s is compressed with %s, which wdyapt cannot read (the Go standard library has no %s); rebuild the package with gzip, e.g. \"dpkg-deb -Zgzip -b\", or with wdyapt deb build", name, strings.TrimPrefix(name, "control.tar."), strings.TrimPrefix(name, "control.tar."))
	default:
		return fmt.Errorf("%s: unsupported compression", name)
	}
	tr := tar.NewReader(io.LimitReader(r, maxControlSize))
	var control []byte
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		member := strings.TrimPrefix(h.Name, "./")
		switch member {
		case "control":
			if control, err = io.ReadAll(tr); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		case "conffiles":
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			for line := range strings.SplitSeq(string(b), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					i.Conffiles = append(i.Conffiles, line)
				}
			}
		case "preinst", "postinst", "prerm", "postrm", "config", "triggers", "templates":
			i.Scripts = append(i.Scripts, member)
		}
	}
	slices.Sort(i.Scripts)
	if control == nil {
		return fmt.Errorf("%s holds no control file", name)
	}
	p, err := debian.ParseOne(string(control))
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if err := debian.ValidName(p.Get("Package")); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if _, err := debian.ParseVersion(p.Get("Version")); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if src, ok := p.Lookup("Source"); ok {
		name, _, _ := strings.Cut(strings.TrimSpace(src), " ")
		if err := debian.ValidName(name); err != nil {
			return fmt.Errorf("control: Source: %w", err)
		}
	}
	if !debian.ArchNamePattern(p.Get("Architecture")) {
		return fmt.Errorf("control: invalid architecture %q", p.Get("Architecture"))
	}
	i.Control = p
	return nil
}

// readData reads the file list; an error ends up in FilesNote.
func (i *Info) readData(name string, body io.Reader) {
	var r io.Reader
	switch name {
	case "data.tar.gz":
		zr, err := gzip.NewReader(body)
		if err != nil {
			i.FilesNote = fmt.Sprintf("%s: %v", name, err)
			return
		}
		r = zr
	case "data.tar":
		r = body
	default:
		i.FilesNote = fmt.Sprintf("%s: wdyapt cannot decompress %s, so the list of files is not shown", name, strings.TrimPrefix(name, "data.tar."))
		return
	}
	tr := tar.NewReader(r)
	files := []FileInfo{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			i.FilesNote = fmt.Sprintf("%s: %v", name, err)
			return
		}
		f := FileInfo{Path: h.Name, Mode: h.Mode & 0o7777, Size: h.Size, Link: h.Linkname}
		switch h.Typeflag {
		case tar.TypeReg:
			f.Type = "file"
		case tar.TypeDir:
			f.Type = "dir"
		case tar.TypeSymlink:
			f.Type = "symlink"
		case tar.TypeLink:
			f.Type = "hardlink"
		default:
			f.Type = "other"
		}
		files = append(files, f)
	}
	i.Files = files
}

// ReadBytes reads a package from memory.
func ReadBytes(data []byte, withFiles bool) (*Info, error) {
	return Read(bytes.NewReader(data), withFiles)
}
