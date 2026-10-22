package repo

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/deb"
	"github.com/worldiety/wdyapt/internal/debian"
)

// Package is a package to be published.
type Package struct {
	Info *deb.Info
	// Name names the package in messages, such as the local path.
	Name string
	// Open returns the content for the upload.
	Open func() (io.ReadCloser, error)
}

// PoolRef is what is known about a file in the pool.
type PoolRef struct {
	Size   int64
	SHA256 string
	// Suite names the suite whose list references the file; empty for a
	// file that no list references.
	Suite string
}

// MergeOptions controls Merge.
type MergeOptions struct {
	Component string
	// Create allows a new suite.
	Create bool
	// Architectures adds to the architectures of the suite.
	Architectures []string
	// Origin, Label, Codename and Description apply to a new suite; for an
	// existing one they must be equal if given.
	Origin, Label, Codename, Description string
	// Date is the desired date of the new Release.
	Date time.Time
	// Known are pool files referenced by lists of other suites, by path.
	Known map[string]PoolRef
	// Existing reports a pool file that no list references; nil if it does
	// not exist. It may download the file to hash it.
	Existing func(path string) (*PoolRef, error)
}

// PoolUpload is a file that must go into the pool.
type PoolUpload struct {
	Path    string
	Package *Package
	// Leftover reports an existing file that no list references and that
	// has different content; it is replaced.
	Leftover bool
}

// IndexFile is a new package list, path relative to the root.
type IndexFile struct {
	Path string
	Data []byte
}

// Ref names a package in the result.
type Ref struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

// Plan is the new state of a suite, ready to be signed and uploaded.
type Plan struct {
	Suite       string
	PoolUploads []PoolUpload
	// Indices are Packages and Packages.gz of the changed lists in the order
	// in which they are switched.
	Indices []IndexFile
	Release []byte
	Date    time.Time
	Added   []Ref
	// Unchanged are packages that already exist with the same bytes.
	Unchanged []Ref
	// Reused are pool files that are already there and stay.
	Reused []string
	// NewArchitectures and NewComponents are new in the suite.
	NewArchitectures, NewComponents []string
	Warnings                        []string
}

// Changed reports whether there is anything to write.
func (p *Plan) Changed() bool {
	return len(p.Added) > 0 || len(p.NewArchitectures) > 0 || len(p.NewComponents) > 0
}

// Merge adds pkgs to the suite in state without ever removing an entry or
// replacing a published package: a package with the same name, version and
// architecture and the same bytes is unchanged, with different bytes it is
// an error (R-REPO-NEVER-REPLACE). Packages of architecture all are in every
// list of their component. Header fields and unknown fields of the Release
// stay; Date, Architectures, Components and the checksums are set anew
// (R-REPO-KEEP-RELEASE-FIELDS). The same state, the same packages and the
// same date yield the same bytes (R-NFR-REPRODUCIBILITY).
func Merge(state *SuiteState, pkgs []*Package, opts MergeOptions) (*Plan, error) {
	plan := &Plan{Suite: state.Suite}
	comp := opts.Component
	if comp == "" {
		comp = "main"
	}
	if err := ValidComponent(comp); err != nil {
		return nil, err
	}
	if !state.Exists && !opts.Create {
		return nil, fmt.Errorf("the suite %q does not exist; check --suite, or give --create to create it", state.Suite)
	}
	if state.Exists {
		for _, f := range []struct{ field, value string }{
			{"Origin", opts.Origin}, {"Label", opts.Label}, {"Codename", opts.Codename}, {"Description", opts.Description},
		} {
			if have := state.Release.Get(f.field); f.value != "" && f.value != have {
				return nil, fmt.Errorf("the suite %s has %s %q; wdyapt never changes it, so --%s %q is an error", state.Suite, f.field, have, strings.ToLower(f.field), f.value)
			}
		}
	}

	// Packages: duplicates with the same content count once.
	byKey := map[string]*Package{}
	var order []string
	for _, p := range pkgs {
		key := p.Info.Name() + " " + p.Info.Version() + " " + p.Info.Arch()
		if prev, ok := byKey[key]; ok {
			if prev.Info.SHA256 != p.Info.SHA256 {
				return nil, fmt.Errorf("%s and %s are both %s %s for %s, with different content", prev.Name, p.Name, p.Info.Name(), p.Info.Version(), p.Info.Arch())
			}
			continue
		}
		byKey[key] = p
		order = append(order, key)
	}
	slices.Sort(order)

	// Architectures and components of the suite.
	oldArches, oldComps := state.Architectures(), state.Components()
	arches := slices.Clone(oldArches)
	add := func(a string) error {
		if a == "all" {
			return nil
		}
		if !debian.ArchNamePattern(a) {
			return fmt.Errorf("invalid architecture %q", a)
		}
		if !slices.Contains(arches, a) {
			arches = append(arches, a)
		}
		return nil
	}
	for _, a := range opts.Architectures {
		if err := add(a); err != nil {
			return nil, err
		}
	}
	for _, key := range order {
		if err := add(byKey[key].Info.Arch()); err != nil {
			return nil, err
		}
	}
	if len(arches) == 0 {
		return nil, fmt.Errorf("the new suite %s would have no architecture: packages for all need --architectures, e.g. amd64,arm64", state.Suite)
	}
	slices.Sort(arches)
	comps := slices.Clone(oldComps)
	if !slices.Contains(comps, comp) {
		comps = append(comps, comp)
	}
	slices.Sort(comps)
	for _, a := range arches {
		if !slices.Contains(oldArches, a) {
			plan.NewArchitectures = append(plan.NewArchitectures, a)
		}
	}
	for _, c := range comps {
		if !slices.Contains(oldComps, c) {
			plan.NewComponents = append(plan.NewComponents, c)
		}
	}

	// Lists: every architecture of every component has one. A new list gets
	// the packages for all that already exist in the component.
	lists := map[ListKey][]debian.Paragraph{}
	for k, v := range state.Lists {
		lists[k] = slices.Clone(v)
	}
	changed := map[ListKey]bool{}
	for _, c := range comps {
		for _, a := range arches {
			k := ListKey{Component: c, Arch: a}
			if _, ok := lists[k]; ok {
				continue
			}
			lists[k] = archAllEntries(state.Lists, c)
			changed[k] = true
		}
	}

	// What is in the pool: this suite and the others.
	known := maps.Clone(opts.Known)
	if known == nil {
		known = map[string]PoolRef{}
	}
	for _, entries := range state.Lists {
		for _, e := range entries {
			size, _ := strconv.ParseInt(e.Get("Size"), 10, 64)
			known[e.Get("Filename")] = PoolRef{Size: size, SHA256: strings.ToLower(e.Get("SHA256")), Suite: state.Suite}
		}
	}
	uploaded := map[string]bool{}

	for _, key := range order {
		p := byKey[key]
		info := p.Info
		pool := info.PoolPath(comp)
		if err := checkFilename(pool); err != nil {
			return nil, err
		}
		ref := Ref{Package: info.Name(), Version: info.Version(), Architecture: info.Arch(), Filename: pool, Size: info.Size, SHA256: info.SHA256}
		var targets []ListKey
		if info.Arch() == "all" {
			for _, a := range arches {
				targets = append(targets, ListKey{Component: comp, Arch: a})
			}
		} else {
			targets = []ListKey{{Component: comp, Arch: info.Arch()}}
		}
		added := false
		for _, k := range targets {
			i := slices.IndexFunc(lists[k], func(e debian.Paragraph) bool {
				return e.Get("Package") == info.Name() && e.Get("Version") == info.Version() && e.Get("Architecture") == info.Arch()
			})
			if i >= 0 {
				if !strings.EqualFold(lists[k][i].Get("SHA256"), info.SHA256) {
					return nil, fmt.Errorf("%s: %s %s for %s is already published in %s with other content; packages are never replaced, build a new version", p.Name, info.Name(), info.Version(), info.Arch(), state.Suite)
				}
				continue
			}
			lists[k] = append(lists[k], entryOf(info, pool))
			changed[k], added = true, true
		}
		if !added {
			plan.Unchanged = append(plan.Unchanged, ref)
			continue
		}
		plan.Added = append(plan.Added, ref)
		if uploaded[pool] {
			continue
		}
		uploaded[pool] = true
		if have, ok := known[pool]; ok {
			if have.SHA256 != info.SHA256 || have.Size != info.Size {
				return nil, fmt.Errorf("%s: the pool file %s exists with other content and suite %s names it; build a new version", p.Name, pool, have.Suite)
			}
			plan.Reused = append(plan.Reused, pool)
			continue
		}
		var have *PoolRef
		if opts.Existing != nil {
			var err error
			if have, err = opts.Existing(pool); err != nil {
				return nil, err
			}
		}
		switch {
		case have == nil:
			plan.PoolUploads = append(plan.PoolUploads, PoolUpload{Path: pool, Package: p})
		case have.SHA256 == info.SHA256 && have.Size == info.Size:
			plan.Reused = append(plan.Reused, pool)
		default:
			plan.PoolUploads = append(plan.PoolUploads, PoolUpload{Path: pool, Package: p, Leftover: true})
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s exists with other content, but no suite names it (left by an interrupted run?); it is replaced", pool))
		}
	}
	if !plan.Changed() {
		return plan, nil
	}

	// Write the changed lists.
	var keys []ListKey
	for k := range changed {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b ListKey) int { return strings.Compare(a.Path(), b.Path()) })
	newSums := map[string][]byte{}
	for _, k := range keys {
		entries := lists[k]
		sortEntries(entries)
		plain := []byte(debian.Format(entries))
		gz, err := gzipBytes(plain)
		if err != nil {
			return nil, err
		}
		dist := state.Dist()
		plan.Indices = append(plan.Indices, IndexFile{Path: dist + k.Path() + ".gz", Data: gz}, IndexFile{Path: dist + k.Path(), Data: plain})
		newSums[k.Path()] = plain
		newSums[k.Path()+".gz"] = gz
		for _, ext := range []string{".xz", ".bz2", ".zst", ".lzma"} {
			if _, ok := state.Files[k.Path()+ext]; ok {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s%s%s cannot be written by wdyapt and is dropped from Release; apt uses Packages.gz", state.Dist(), k.Path(), ext))
			}
		}
	}

	// Date: never before or equal to the old one, else apt rejects the state.
	date := opts.Date.UTC().Truncate(time.Second)
	if state.Exists && !date.After(state.Date) {
		date = state.Date.Add(time.Second)
	}
	plan.Date = date
	if d := time.Until(date); d > time.Minute {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("the new Date %s lies %s in the future; apt rejects a Release from the future", FormatDate(date), d.Round(time.Second)))
	}

	var release debian.Paragraph
	fields := []string{"MD5Sum", "SHA256"}
	if state.Exists {
		release = state.Release.Clone()
		fields = state.Fields
		release = release.Set("Date", FormatDate(date))
		if len(plan.NewArchitectures) > 0 {
			release = setBefore(release, "Architectures", strings.Join(arches, " "))
		}
		if len(plan.NewComponents) > 0 {
			release = setBefore(release, "Components", strings.Join(comps, " "))
		}
		for _, f := range checksumFields {
			release = release.Delete(f)
		}
	} else {
		codename := opts.Codename
		if codename == "" {
			codename = state.Suite
		}
		if opts.Origin != "" {
			release = append(release, debian.Field{Key: "Origin", Value: opts.Origin})
		}
		if opts.Label != "" {
			release = append(release, debian.Field{Key: "Label", Value: opts.Label})
		}
		release = append(release,
			debian.Field{Key: "Suite", Value: state.Suite},
			debian.Field{Key: "Codename", Value: codename},
			debian.Field{Key: "Date", Value: FormatDate(date)},
			debian.Field{Key: "Architectures", Value: strings.Join(arches, " ")},
			debian.Field{Key: "Components", Value: strings.Join(comps, " ")},
		)
		if opts.Description != "" {
			release = append(release, debian.Field{Key: "Description", Value: opts.Description})
		}
		release = append(release, debian.Field{Key: "Changelogs", Value: "no"})
	}

	// Checksums: unchanged files as read, changed ones anew; variants of
	// changed lists that wdyapt does not write are dropped.
	var names []string
	for name := range state.Files {
		if k, ok := listKeyOf(name); ok && changed[k] {
			continue
		}
		names = append(names, name)
	}
	for name := range newSums {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, field := range fields {
		var b strings.Builder
		for _, name := range names {
			if data, ok := newSums[name]; ok {
				fmt.Fprintf(&b, "\n %s %d %s", sumHex(field, data), len(data), name)
			} else if sum, ok := state.Files[name].Sums[field]; ok {
				fmt.Fprintf(&b, "\n %s %d %s", sum, state.Files[name].Size, name)
			}
		}
		release = append(release, debian.Field{Key: field, Value: b.String()})
	}
	plan.Release = []byte(release.String())
	return plan, nil
}

// setBefore sets a field in its place or, if it is missing, before the
// checksums.
func setBefore(p debian.Paragraph, key, value string) debian.Paragraph {
	if _, ok := p.Lookup(key); ok {
		return p.Set(key, value)
	}
	for _, f := range checksumFields {
		if _, ok := p.Lookup(f); ok {
			return p.Insert(f, debian.Field{Key: key, Value: value})
		}
	}
	return append(p, debian.Field{Key: key, Value: value})
}

// archAllEntries collects the packages for all of a component from all
// lists, each once.
func archAllEntries(lists map[ListKey][]debian.Paragraph, comp string) []debian.Paragraph {
	seen := map[string]bool{}
	var out []debian.Paragraph
	var keys []ListKey
	for k := range lists {
		if k.Component == comp {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b ListKey) int { return strings.Compare(a.Arch, b.Arch) })
	for _, k := range keys {
		for _, e := range lists[k] {
			if e.Get("Architecture") != "all" {
				continue
			}
			id := e.Get("Package") + " " + e.Get("Version")
			if !seen[id] {
				seen[id] = true
				out = append(out, e.Clone())
			}
		}
	}
	return out
}

// entryOf is the entry of a package in Packages: the fields of the control
// file in their order, with Filename, Size, MD5sum and SHA256 inserted
// before Description.
func entryOf(info *deb.Info, pool string) debian.Paragraph {
	e := info.Control.Clone()
	for _, f := range []string{"Filename", "Size", "MD5sum", "SHA256", "SHA1", "SHA512", "Status"} {
		e = e.Delete(f)
	}
	for _, f := range []debian.Field{
		{Key: "Filename", Value: pool},
		{Key: "Size", Value: strconv.FormatInt(info.Size, 10)},
		{Key: "MD5sum", Value: info.MD5},
		{Key: "SHA256", Value: info.SHA256},
	} {
		e = e.Insert("Description", f)
	}
	return e
}

// sortEntries sorts by Package, Version (like dpkg) and Architecture.
func sortEntries(entries []debian.Paragraph) {
	slices.SortStableFunc(entries, func(a, b debian.Paragraph) int {
		if c := strings.Compare(a.Get("Package"), b.Get("Package")); c != 0 {
			return c
		}
		if c := debian.CompareVersions(a.Get("Version"), b.Get("Version")); c != 0 {
			return c
		}
		return strings.Compare(a.Get("Architecture"), b.Get("Architecture"))
	})
}

// gzipBytes compresses data without name and time, so always the same.
func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	err = zw.Close()
	return buf.Bytes(), err
}
