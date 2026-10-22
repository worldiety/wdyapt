// Package repo knows the format of an APT repository: it reads the
// published state of a suite and verifies it (R-REPO-CHECK-STATE), merges
// new packages and writes package lists and Release (R-REPO-NEVER-REPLACE,
// R-REPO-KEEP-RELEASE-FIELDS), lists and verifies a repository
// (R-REPO-LIST, R-REPO-VERIFY). Input and output happen read-only through
// store.Reader; writing happens in publish.
package repo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/debian"
	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/store"
)

// Limits for reading a state that comes from the server and may be
// hostile.
const (
	maxRelease = 16 << 20
	maxList    = 512 << 20
)

// LockFile is the lock of a running publication.
const LockFile = ".wdyapt.lock"

// Checksum blocks in the Release in the order in which apt prefers to read
// them; wdyapt writes MD5Sum and SHA256 and keeps maintaining existing SHA1
// and SHA512.
var checksumFields = []string{"MD5Sum", "SHA1", "SHA256", "SHA512"}

func newSum(field string) hash.Hash {
	switch field {
	case "MD5Sum":
		return md5.New()
	case "SHA1":
		return sha1.New()
	case "SHA256":
		return sha256.New()
	default:
		return sha512.New()
	}
}

func sumHex(field string, data []byte) string {
	h := newSum(field)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

var suitePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// ValidSuite checks the name of a suite.
func ValidSuite(name string) error {
	if !suitePattern.MatchString(name) {
		return fmt.Errorf("invalid suite name %q: use letters, digits, '.', '_', '+' and '-'", name)
	}
	return nil
}

// ValidComponent checks the name of a component.
func ValidComponent(name string) error {
	if !suitePattern.MatchString(name) {
		return fmt.Errorf("invalid component name %q: use letters, digits, '.', '_', '+' and '-'", name)
	}
	return nil
}

// ListKey identifies a package list: component and architecture.
type ListKey struct {
	Component string
	Arch      string
}

// Path is the path of the list relative to dists/<suite>/.
func (k ListKey) Path() string { return k.Component + "/binary-" + k.Arch + "/Packages" }

// FileSum is what the Release says about a file.
type FileSum struct {
	Size int64
	// Lines are the checksum lines per block, as read.
	Sums map[string]string
}

// SuiteState is the verified state of a suite.
type SuiteState struct {
	Suite  string
	Exists bool
	// Checked reports that the signature is verified; when read without a
	// keyring it is not.
	Checked bool
	Release debian.Paragraph
	// Raw and RawName are the file that shows before switching whether
	// another run has changed the suite in the meantime.
	Raw     []byte
	RawName string
	Signers []openpgp.SignatureInfo
	Date    time.Time
	// Files are the files that the Release references, relative to
	// dists/<suite>/.
	Files map[string]FileSum
	// Lists are the entries per package list.
	Lists map[ListKey][]debian.Paragraph
	// Fields are the checksum blocks that the Release has.
	Fields []string
}

// Dist is dists/<suite>/.
func (s *SuiteState) Dist() string { return "dists/" + s.Suite + "/" }

// Architectures returns the architectures from the Release.
func (s *SuiteState) Architectures() []string { return strings.Fields(s.Release.Get("Architectures")) }

// Components returns the components from the Release.
func (s *SuiteState) Components() []string { return strings.Fields(s.Release.Get("Components")) }

// ChecksumError reports a file that does not match its checksum in the
// Release. An aborted run can leave this behind; publish then tries to
// complete it.
type ChecksumError struct {
	Suite, File, Reason string
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf("dists/%s/%s %s; either a publish was interrupted (run publish again, it completes an interrupted run it can verify) or someone changed the repository: compare with a backup and repair it by hand", e.Suite, e.File, e.Reason)
}

// ReadSuite reads the state of the suite and verifies it: the signature of
// InRelease or Release.gpg against ring, the same text in InRelease and
// Release, every package list referenced in the SHA256 block against size
// and SHA256, and every entry. If there is neither InRelease nor Release,
// the suite counts as absent; then there must be nothing else under
// dists/<suite>/ either. With ring nil the signature is not verified (only
// for repo list). Errors name the file and what to do (R-REPO-CHECK-STATE).
func ReadSuite(ctx context.Context, st store.Reader, suite string, ring *openpgp.Keyring) (*SuiteState, error) {
	if err := ValidSuite(suite); err != nil {
		return nil, err
	}
	s := &SuiteState{Suite: suite, Files: map[string]FileSum{}, Lists: map[ListKey][]debian.Paragraph{}}
	dist := s.Dist()
	read := func(name string) ([]byte, error) {
		data, err := store.ReadLimited(ctx, st, dist+name, maxRelease)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s%s: %w", dist, name, err)
		}
		return data, nil
	}
	inRelease, err := read("InRelease")
	if err != nil {
		return nil, err
	}
	release, err := read("Release")
	if err != nil {
		return nil, err
	}
	releaseGPG, err := read("Release.gpg")
	if err != nil {
		return nil, err
	}
	if inRelease == nil && release == nil {
		if err := checkNothingThere(ctx, st, dist); err != nil {
			return nil, err
		}
		return s, nil
	}
	s.Exists = true

	var text []byte
	switch {
	case inRelease != nil:
		s.Raw, s.RawName = inRelease, "InRelease"
		if ring == nil {
			text, err = openpgp.ParseCleartext(inRelease)
		} else {
			text, s.Signers, err = ring.VerifyCleartext(inRelease)
		}
		if err != nil {
			return nil, fmt.Errorf("%sInRelease: %w", dist, err)
		}
		if release != nil && !bytes.Equal(text, release) {
			return nil, fmt.Errorf("%sInRelease and %sRelease differ; a publish was interrupted or someone changed the repository: run publish again or repair it by hand", dist, dist)
		}
		if release != nil && releaseGPG != nil && ring != nil {
			if _, err := ring.VerifyDetached(release, releaseGPG); err != nil {
				return nil, fmt.Errorf("%sRelease.gpg: %w", dist, err)
			}
		}
	default:
		s.Raw, s.RawName, text = release, "Release", release
		if ring != nil {
			if releaseGPG == nil {
				return nil, fmt.Errorf("%sRelease is not signed: there is neither InRelease nor Release.gpg; repair the repository by hand", dist)
			}
			if s.Signers, err = ring.VerifyDetached(release, releaseGPG); err != nil {
				return nil, fmt.Errorf("%sRelease.gpg: %w", dist, err)
			}
		}
	}
	s.Checked = ring != nil

	p, err := debian.ParseOne(string(text))
	if err != nil {
		return nil, fmt.Errorf("%sRelease: %w", dist, err)
	}
	s.Release = p
	if _, ok := p.Lookup("Valid-Until"); ok {
		return nil, fmt.Errorf("%sRelease has Valid-Until; wdyapt cannot keep it current, so apt would reject the suite later: remove the field from the suite by hand first", dist)
	}
	if strings.EqualFold(p.Get("Acquire-By-Hash"), "yes") {
		return nil, fmt.Errorf("%sRelease announces Acquire-By-Hash, which wdyapt does not write; remove the field by hand first", dist)
	}
	if s.Date, err = ParseDate(p.Get("Date")); err != nil {
		return nil, fmt.Errorf("%sRelease: Date: %w", dist, err)
	}
	for _, field := range checksumFields {
		value, ok := p.Lookup(field)
		if !ok {
			continue
		}
		s.Fields = append(s.Fields, field)
		for _, line := range debian.Lines(value) {
			f := strings.Fields(line)
			if len(f) != 3 {
				return nil, fmt.Errorf("%sRelease: broken %s line %q", dist, field, line)
			}
			size, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil || size < 0 {
				return nil, fmt.Errorf("%sRelease: broken size in %q", dist, line)
			}
			name, err := store.Clean(f[2])
			if err != nil {
				return nil, fmt.Errorf("%sRelease: %w", dist, err)
			}
			fsum, ok := s.Files[name]
			if !ok {
				fsum = FileSum{Size: size, Sums: map[string]string{}}
			} else if fsum.Size != size {
				return nil, fmt.Errorf("%sRelease names two sizes for %s", dist, name)
			}
			fsum.Sums[field] = strings.ToLower(f[0])
			s.Files[name] = fsum
		}
	}
	if !slices.Contains(s.Fields, "SHA256") {
		return nil, fmt.Errorf("%sRelease has no SHA256 checksums; apt does not trust such a suite", dist)
	}
	if err := s.readLists(ctx, st); err != nil {
		return nil, err
	}
	return s, nil
}

// checkNothingThere checks that there is nothing under dist except
// temporary files.
func checkNothingThere(ctx context.Context, st store.Reader, dist string) error {
	entries, err := st.ReadDir(ctx, strings.TrimSuffix(dist, "/"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case errors.Is(err, store.ErrNoListing):
		// Over HTTP it is enough not to find the usual lists.
		return nil
	case err != nil:
		return fmt.Errorf("reading %s: %w", dist, err)
	}
	for _, e := range entries {
		if !store.IsTemp(e.Name()) {
			return fmt.Errorf("%s has no Release, but contains %s; repair the repository by hand", dist, e.Name())
		}
	}
	return nil
}

// readLists reads every package list that the Release references and
// verifies it.
func (s *SuiteState) readLists(ctx context.Context, st store.Reader) error {
	keys := map[ListKey]bool{}
	for name := range s.Files {
		if k, ok := listKeyOf(name); ok {
			keys[k] = true
		}
	}
	for k := range keys {
		var entries []debian.Paragraph
		var got bool
		for _, variant := range []string{"", ".gz"} {
			name := k.Path() + variant
			sum, listed := s.Files[name]
			if !listed {
				continue
			}
			data, err := s.readChecked(ctx, st, name, sum)
			if err != nil {
				return err
			}
			if variant == ".gz" {
				zr, err := gzip.NewReader(bytes.NewReader(data))
				if err != nil {
					return fmt.Errorf("%s%s: %w", s.Dist(), name, err)
				}
				if data, err = io.ReadAll(io.LimitReader(zr, maxList+1)); err != nil {
					return fmt.Errorf("%s%s: %w", s.Dist(), name, err)
				}
				if len(data) > maxList {
					return fmt.Errorf("%s%s is larger than %d bytes unpacked", s.Dist(), name, maxList)
				}
			}
			parsed, err := parseList(string(data))
			if err != nil {
				return fmt.Errorf("%s%s: %w", s.Dist(), name, err)
			}
			if got && !sameEntries(entries, parsed) {
				return fmt.Errorf("%s%s and its uncompressed list differ; repair the repository by hand", s.Dist(), name)
			}
			entries, got = parsed, true
		}
		if !got {
			return fmt.Errorf("%s%s is listed only in a compression wdyapt cannot read (xz, bz2 or zstd)", s.Dist(), k.Path())
		}
		s.Lists[k] = entries
	}
	return nil
}

// readChecked reads a file and verifies size and checksums from the
// Release.
func (s *SuiteState) readChecked(ctx context.Context, st store.Reader, name string, sum FileSum) ([]byte, error) {
	data, err := store.ReadLimited(ctx, st, s.Dist()+name, maxList)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, &ChecksumError{Suite: s.Suite, File: name, Reason: "is listed in Release but missing"}
	}
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != sum.Size {
		return nil, &ChecksumError{Suite: s.Suite, File: name, Reason: fmt.Sprintf("has %d bytes, but Release says %d", len(data), sum.Size)}
	}
	for field, want := range sum.Sums {
		if sumHex(field, data) != want {
			return nil, &ChecksumError{Suite: s.Suite, File: name, Reason: "does not match its " + field + " checksum in Release"}
		}
	}
	return data, nil
}

// listKeyOf recognizes a package list under <component>/binary-<arch>/.
func listKeyOf(name string) (ListKey, bool) {
	dir, base := path.Split(name)
	if !strings.HasPrefix(base, "Packages") {
		return ListKey{}, false
	}
	if ext := strings.TrimPrefix(base, "Packages"); ext != "" && !slices.Contains([]string{".gz", ".xz", ".bz2", ".zst", ".lzma"}, ext) {
		return ListKey{}, false
	}
	dir = strings.TrimSuffix(dir, "/")
	comp, arch, ok := strings.Cut(dir, "/binary-")
	if !ok || comp == "" || strings.Contains(arch, "/") || !debian.ArchNamePattern(arch) {
		return ListKey{}, false
	}
	return ListKey{Component: comp, Arch: arch}, true
}

// parseList reads a package list and checks every entry.
func parseList(text string) ([]debian.Paragraph, error) {
	entries, err := debian.Parse(text)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		for _, f := range []string{"Package", "Version", "Architecture", "Filename", "Size", "SHA256"} {
			if strings.TrimSpace(e.Get(f)) == "" {
				return nil, fmt.Errorf("the entry %s %s lacks %s", e.Get("Package"), e.Get("Version"), f)
			}
		}
		if err := checkFilename(e.Get("Filename")); err != nil {
			return nil, fmt.Errorf("the entry %s %s: %w", e.Get("Package"), e.Get("Version"), err)
		}
		if n, err := strconv.ParseInt(e.Get("Size"), 10, 64); err != nil || n < 0 {
			return nil, fmt.Errorf("the entry %s %s has a broken Size", e.Get("Package"), e.Get("Version"))
		}
	}
	return entries, nil
}

// checkFilename allows only paths under pool/ without "..".
func checkFilename(name string) error {
	c, err := store.Clean(name)
	if err != nil || !strings.HasPrefix(c, "pool/") {
		return fmt.Errorf("Filename %q does not lie below pool/", name)
	}
	return nil
}

func sameEntries(a, b []debian.Paragraph) bool {
	return debian.Format(a) == debian.Format(b)
}

// ParseDate reads Date from a Release, as apt writes and reads it.
func ParseDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC1123, time.RFC1123Z, "Mon, 2 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05 -0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot read %q", s)
}

// FormatDate writes Date like apt-ftparchive: RFC 1123 in UTC.
func FormatDate(t time.Time) string {
	return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC")
}

// Suites returns the names of the suites under dists/.
func Suites(ctx context.Context, st store.Reader) ([]string, error) {
	entries, err := st.ReadDir(ctx, "dists")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && ValidSuite(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}
