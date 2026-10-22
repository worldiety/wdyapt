package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/worldiety/wdyapt/internal/debian"
	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/store"
)

// Entry is a package in a list.
type Entry struct {
	Component    string `json:"component"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Size         int64  `json:"size"`
	Filename     string `json:"filename"`
	SHA256       string `json:"sha256"`
}

// Filter narrows List; empty fields do not apply.
type Filter struct {
	Component, Arch, Package string
}

// List returns the packages of a suite, each once, sorted by component,
// package, version and architecture (R-REPO-LIST). A package for all is in
// several lists but appears only once, unless Filter.Arch asks for an
// architecture.
func List(state *SuiteState, f Filter) []Entry {
	seen := map[string]bool{}
	var out []Entry
	for k, entries := range state.Lists {
		if f.Component != "" && k.Component != f.Component || f.Arch != "" && k.Arch != f.Arch {
			continue
		}
		for _, e := range entries {
			if f.Package != "" && e.Get("Package") != f.Package {
				continue
			}
			size, _ := strconv.ParseInt(e.Get("Size"), 10, 64)
			x := Entry{Component: k.Component, Package: e.Get("Package"), Version: e.Get("Version"), Architecture: e.Get("Architecture"),
				Size: size, Filename: e.Get("Filename"), SHA256: strings.ToLower(e.Get("SHA256"))}
			id := x.Component + " " + x.Package + " " + x.Version + " " + x.Architecture
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, x)
		}
	}
	slices.SortFunc(out, func(a, b Entry) int {
		if c := strings.Compare(a.Component, b.Component); c != 0 {
			return c
		}
		if c := strings.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		if c := debian.CompareVersions(a.Version, b.Version); c != 0 {
			return c
		}
		return strings.Compare(a.Architecture, b.Architecture)
	})
	return out
}

// Problem is a defect that Verify finds.
type Problem struct {
	Suite   string `json:"suite,omitempty"`
	File    string `json:"file,omitempty"`
	Message string `json:"message"`
}

func (p Problem) String() string {
	var parts []string
	if p.Suite != "" {
		parts = append(parts, "suite "+p.Suite)
	}
	if p.File != "" {
		parts = append(parts, p.File)
	}
	if len(parts) == 0 {
		return p.Message
	}
	return strings.Join(parts, ", ") + ": " + p.Message
}

// VerifyOptions controls Verify.
type VerifyOptions struct {
	// Suites checks only these; empty means all under dists/.
	Suites []string
	// CheckPool also checks the SHA256 of every pool file.
	CheckPool bool
	// Progress reports what is being checked; may be nil.
	Progress func(format string, args ...any)
}

// VerifyResult is the result of Verify.
type VerifyResult struct {
	Suites   []string  `json:"suites"`
	Packages int       `json:"packages"`
	Problems []Problem `json:"problems"`
}

// Verify checks a published repository: signatures and checksums of every
// suite, that every referenced pool file is present with the right size
// (with CheckPool also with the right SHA256), and whether temporary files
// or a lock were left behind. It reports all defects (R-REPO-VERIFY).
func Verify(ctx context.Context, st store.Reader, ring *openpgp.Keyring, opts VerifyOptions) (*VerifyResult, error) {
	res := &VerifyResult{Problems: []Problem{}}
	say := func(format string, args ...any) {
		if opts.Progress != nil {
			opts.Progress(format, args...)
		}
	}
	suites := opts.Suites
	if len(suites) == 0 {
		var err error
		suites, err = Suites(ctx, st)
		if errors.Is(err, store.ErrNoListing) {
			return nil, fmt.Errorf("%w: give --suite", err)
		}
		if err != nil {
			return nil, err
		}
		if len(suites) == 0 {
			res.Problems = append(res.Problems, Problem{Message: "there is no suite below dists/"})
		}
	}
	res.Suites = suites
	checked := map[string]bool{}
	for _, suite := range suites {
		say("Checking suite %s", suite)
		state, err := ReadSuite(ctx, st, suite, ring)
		if err != nil {
			res.Problems = append(res.Problems, Problem{Suite: suite, Message: err.Error()})
			continue
		}
		if !state.Exists {
			res.Problems = append(res.Problems, Problem{Suite: suite, Message: "the suite does not exist"})
			continue
		}
		for _, k := range sortedKeys(state.Lists) {
			for _, e := range state.Lists[k] {
				res.Packages++
				name := e.Get("Filename")
				if checked[name] {
					continue
				}
				checked[name] = true
				size, _ := strconv.ParseInt(e.Get("Size"), 10, 64)
				if p := checkPoolFile(ctx, st, name, size, strings.ToLower(e.Get("SHA256")), opts.CheckPool); p != "" {
					res.Problems = append(res.Problems, Problem{Suite: suite, File: name, Message: p})
				}
			}
		}
	}
	// Leftovers of our own runs.
	if _, err := st.Stat(ctx, LockFile); err == nil {
		owner := "unknown"
		if data, err := store.ReadLimited(ctx, st, LockFile, 64<<10); err == nil {
			owner = strings.TrimSpace(string(data))
		}
		res.Problems = append(res.Problems, Problem{File: LockFile, Message: "a lock is held or was left by an interrupted publish: " + owner + "; remove it with publish --break-lock once no publish runs"})
	}
	temps, err := findTemp(ctx, st)
	if err != nil && !errors.Is(err, store.ErrNoListing) {
		return nil, err
	}
	for _, t := range temps {
		res.Problems = append(res.Problems, Problem{File: t, Message: "temporary file of an interrupted publish; run publish again to complete it, or remove the file"})
	}
	return res, nil
}

// checkPoolFile checks a pool file; empty means fine.
func checkPoolFile(ctx context.Context, st store.Reader, name string, size int64, sha string, full bool) string {
	info, err := st.Stat(ctx, name)
	if errors.Is(err, fs.ErrNotExist) {
		return "missing"
	}
	if err != nil {
		return err.Error()
	}
	if info.Size() != size {
		return fmt.Sprintf("has %d bytes, the package list says %d", info.Size(), size)
	}
	if !full {
		return ""
	}
	got, _, err := HashFile(ctx, st, name)
	if err != nil {
		return err.Error()
	}
	if got != sha {
		return "does not match its SHA256 in the package list"
	}
	return ""
}

// HashFile returns the SHA256 and size of a file on the storage.
func HashFile(ctx context.Context, st store.Reader, name string) (string, int64, error) {
	f, err := st.Open(ctx, name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := newSum("SHA256")
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("reading %s: %w", name, err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), n, nil
}

// findTemp looks for temporary files of our own runs under dists/ and pool/.
func findTemp(ctx context.Context, st store.Reader) ([]string, error) {
	var out []string
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := st.ReadDir(ctx, dir)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := path.Join(dir, e.Name())
			switch {
			case e.IsDir():
				if err := walk(name); err != nil {
					return err
				}
			case store.IsTemp(name):
				out = append(out, name)
			}
		}
		return nil
	}
	for _, dir := range []string{"dists", "pool"} {
		if err := walk(dir); err != nil {
			return out, err
		}
	}
	slices.Sort(out)
	return out, nil
}

func sortedKeys[V any](m map[ListKey]V) []ListKey {
	keys := make([]ListKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b ListKey) int { return strings.Compare(a.Path(), b.Path()) })
	return keys
}
