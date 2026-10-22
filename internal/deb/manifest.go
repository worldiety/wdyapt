// Package deb builds Debian binary packages from existing files and reads
// such packages back (R-PKG-BUILD-FROM-FILES, R-PKG-CONTROL-DATA,
// R-PKG-VALIDATE-INPUT, R-PKG-SHOW).
//
// A package is described by a Manifest that comes from a JSON file, from
// command line options or from both. Validate checks it together with all
// source files; Build builds one package per architecture from it.
package deb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest describes a package. The JSON names are lowercase; unknown fields
// are an error.
type Manifest struct {
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	Architectures []string `json:"architectures"`
	Maintainer    string   `json:"maintainer"`
	Summary       string   `json:"summary"`
	Description   string   `json:"description,omitempty"`
	Homepage      string   `json:"homepage,omitempty"`
	Section       string   `json:"section,omitempty"`
	Priority      string   `json:"priority,omitempty"`

	Depends    []string `json:"depends,omitempty"`
	PreDepends []string `json:"pre_depends,omitempty"`
	Recommends []string `json:"recommends,omitempty"`
	Suggests   []string `json:"suggests,omitempty"`
	Conflicts  []string `json:"conflicts,omitempty"`
	Breaks     []string `json:"breaks,omitempty"`
	Replaces   []string `json:"replaces,omitempty"`
	Provides   []string `json:"provides,omitempty"`

	Files       []File            `json:"files,omitempty"`
	Directories []Directory       `json:"directories,omitempty"`
	Symlinks    []Symlink         `json:"symlinks,omitempty"`
	Conffiles   []string          `json:"conffiles,omitempty"`
	Scripts     Scripts           `json:"scripts,omitzero"`
	Fields      map[string]string `json:"fields,omitempty"`

	// Dir is the directory relative sources are resolved from; when reading a
	// manifest file, its directory.
	Dir string `json:"-"`
}

// File is a file of the package. Src may contain {arch} and {uname} and may
// end in "/", in which case the whole directory tree applies.
type File struct {
	Src  string `json:"src"`
	Dst  string `json:"dst"`
	Mode string `json:"mode,omitempty"`
}

// Directory is an empty directory of the package.
type Directory struct {
	Path string `json:"path"`
	Mode string `json:"mode,omitempty"`
}

// Symlink is a symbolic link of the package.
type Symlink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// Scripts are the maintainer scripts, each as the path of a file.
type Scripts struct {
	Preinst  string `json:"preinst,omitempty"`
	Postinst string `json:"postinst,omitempty"`
	Prerm    string `json:"prerm,omitempty"`
	Postrm   string `json:"postrm,omitempty"`
}

// list returns the given scripts in the order dpkg runs them.
func (s Scripts) list() [][2]string {
	var out [][2]string
	for _, p := range [][2]string{{"preinst", s.Preinst}, {"postinst", s.Postinst}, {"prerm", s.Prerm}, {"postrm", s.Postrm}} {
		if p[1] != "" {
			out = append(out, p)
		}
	}
	return out
}

// LoadManifest reads a manifest file. Relative sources are then resolved
// from the directory of the file.
func LoadManifest(name string) (*Manifest, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if m.Dir, err = filepath.Abs(filepath.Dir(name)); err != nil {
		return nil, err
	}
	return m, nil
}

// ParseManifest reads a manifest from JSON; unknown fields and extra
// documents are an error.
func ParseManifest(data []byte) (*Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("invalid manifest: more than one JSON document")
	}
	return &m, nil
}

// source returns the path of a source, relative to Dir.
func (m *Manifest) source(src string) string {
	if filepath.IsAbs(src) || m.Dir == "" {
		return src
	}
	return filepath.Join(m.Dir, src)
}
