package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// entry is a file, a directory or a symlink in a tar archive of the
// package. The name is relative to the root and has no leading "./", such
// as "usr/bin/caddy"; a directory ends in "/".
type entry struct {
	Name   string
	Mode   int64
	Data   []byte
	Target string // target of a symbolic link
}

func (e entry) dir() bool  { return strings.HasSuffix(e.Name, "/") }
func (e entry) link() bool { return e.Target != "" }

// tree adds the directories above the entries and returns all of them
// sorted by name, directories before their contents. An explicitly given
// directory keeps its mode.
func tree(entries []entry) []entry {
	byName := map[string]entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	for _, e := range entries {
		for d := path.Dir(strings.TrimSuffix(e.Name, "/")); d != "." && d != "/"; d = path.Dir(d) {
			if _, ok := byName[d+"/"]; !ok {
				byName[d+"/"] = entry{Name: d + "/", Mode: 0o755}
			}
		}
	}
	all := make([]entry, 0, len(byName))
	for _, e := range byName {
		all = append(all, e)
	}
	slices.SortFunc(all, func(a, b entry) int { return strings.Compare(a.Name, b.Name) })
	return all
}

// tarGz writes entries as tar.gz the way dpkg expects it: GNU format, every
// name prefixed with "./", an entry "./" for the root, everything root:root
// with the timestamp epoch, gzip without name and time. Equal inputs yield
// the same bytes.
func tarGz(entries []entry, epoch time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	write := func(h *tar.Header, data []byte) error {
		h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "root", "root"
		h.ModTime = epoch
		h.Format = tar.FormatGNU
		if err := tw.WriteHeader(h); err != nil {
			return fmt.Errorf("%s: %w", h.Name, err)
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write(&tar.Header{Typeflag: tar.TypeDir, Name: "./", Mode: 0o755}, nil); err != nil {
		return nil, err
	}
	for _, e := range entries {
		h := &tar.Header{Name: "./" + e.Name, Mode: e.Mode}
		switch {
		case e.dir():
			h.Typeflag = tar.TypeDir
		case e.link():
			h.Typeflag, h.Linkname, h.Mode = tar.TypeSymlink, e.Target, 0o777
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e.Data))
		}
		if err := write(h, e.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// member is a file in an ar archive.
type member struct {
	Name string
	Data []byte
}

// writeAr writes members as an ar archive in the common format that dpkg
// requires for .deb files: names without a trailing "/", owner 0, mode
// 100644 and every file padded to an even length.
func writeAr(w io.Writer, members []member, epoch time.Time) error {
	if _, err := io.WriteString(w, "!<arch>\n"); err != nil {
		return err
	}
	for _, m := range members {
		if len(m.Name) > 16 || strings.Contains(m.Name, "/") {
			return fmt.Errorf("ar: name %q does not fit", m.Name)
		}
		h := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", m.Name, epoch.Unix(), 0, 0, "100644", len(m.Data))
		if _, err := io.WriteString(w, h); err != nil {
			return err
		}
		if _, err := w.Write(m.Data); err != nil {
			return err
		}
		if len(m.Data)%2 == 1 {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
	}
	return nil
}

// arReader reads the members of an ar archive one after another.
type arReader struct {
	r       io.Reader
	pending int64 // unread bytes of the current member including padding
}

func newArReader(r io.Reader) (*arReader, error) {
	magic := make([]byte, 8)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != "!<arch>\n" {
		return nil, fmt.Errorf("not a Debian package: no ar archive")
	}
	return &arReader{r: r}, nil
}

// next returns the name and size of the next member and a reader for its
// contents; io.EOF at the end.
func (a *arReader) next() (string, int64, io.Reader, error) {
	if a.pending > 0 {
		if _, err := io.CopyN(io.Discard, a.r, a.pending); err != nil {
			return "", 0, nil, fmt.Errorf("broken ar archive: %w", err)
		}
	}
	h := make([]byte, 60)
	n, err := io.ReadFull(a.r, h)
	if n == 0 && err == io.EOF {
		return "", 0, nil, io.EOF
	}
	if err != nil {
		return "", 0, nil, fmt.Errorf("broken ar archive: truncated header")
	}
	if string(h[58:60]) != "`\n" {
		return "", 0, nil, fmt.Errorf("broken ar archive: bad header %q", h)
	}
	name := strings.TrimSuffix(strings.TrimRight(string(h[:16]), " "), "/")
	size, err := strconv.ParseInt(strings.TrimSpace(string(h[48:58])), 10, 64)
	if err != nil || size < 0 {
		return "", 0, nil, fmt.Errorf("broken ar archive: bad size of %q", name)
	}
	a.pending = size + size%2
	return name, size, &countingReader{r: io.LimitReader(a.r, size), n: &a.pending}, nil
}

// countingReader subtracts the bytes read from n so that next can skip the
// rest.
type countingReader struct {
	r io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n -= int64(n)
	return n, err
}
