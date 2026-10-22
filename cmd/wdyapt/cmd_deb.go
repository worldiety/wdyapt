package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/deb"
)

// debCommand is the group "deb": build and show packages.
func debCommand() *cli.Command {
	return &cli.Command{
		Name:        "deb",
		Summary:     "Build and inspect Debian packages",
		Description: "Commands to build Debian binary packages from files and to show what a package contains.",
		Commands:    []*cli.Command{debBuildCommand(), debInfoCommand()},
	}
}

func debBuildCommand() *cli.Command {
	return &cli.Command{
		Name:    "build",
		Summary: "Build Debian packages from files",
		Description: `Builds one Debian binary package per architecture from files that already exist, such as downloaded programs, systemd units and configuration. The package is described by options or by a JSON manifest (--manifest); options win over the manifest.

Paths of source files may contain {arch}, which becomes the Debian architecture (amd64, arm64, ...), and {uname}, which becomes the name "uname -m" uses (x86_64, aarch64, ...). A source ending in "/" takes the whole directory tree. Relative sources in a manifest are relative to the manifest.

Before building, every input is checked: name, version, architecture, maintainer, target paths, modes, conffiles, scripts, and whether every ELF program fits the architecture. All problems are reported at once and no package is written.

Options replace what the manifest says, lists included. Packages are reproducible: the same inputs and the same --epoch give the same bytes. Each written package is printed as one line, <out>/<name>_<version>_<arch>.deb. An existing file with the same content is left alone; one with other content is an error.

  wdyapt deb build --name caddy --version 2.10.0-1 --arch amd64,arm64 \
    --maintainer "Example <dev@example.com>" --summary "Web server" \
    --file 'downloads/caddy_linux_{arch}:/usr/bin/caddy:0755' \
    --file caddy.service:/usr/lib/systemd/system/caddy.service \
    --out build/`,
		Flags: func(fs *flag.FlagSet) {
			fs.String("manifest", "", "JSON manifest `FILE` that describes the package")
			fs.String("name", "", "package `NAME`, e.g. caddy")
			fs.String("version", "", "Debian `VERSION`, e.g. 2.10.0-1 or 1:2.0~rc1-3")
			fs.Var(&cli.List{Split: true}, "arch", "`LIST` of architectures to build, separated by commas: amd64, arm64, armhf, i386, riscv64, ppc64el, s390x or all")
			fs.String("maintainer", "", "maintainer as `\"NAME <MAIL>\"`")
			fs.String("summary", "", "one line of `TEXT` that describes the package")
			fs.String("description", "", "long description `TEXT`; paragraphs are separated by an empty line")
			fs.String("description-file", "", "read the long description from `FILE`")
			fs.String("homepage", "", "`URL` of the project")
			fs.String("section", "", "archive `SECTION` (default misc)")
			fs.String("priority", "", "`PRIORITY` of the package (default optional)")
			for _, rel := range []string{"depends", "pre-depends", "recommends", "suggests", "conflicts", "breaks", "replaces", "provides"} {
				fs.Var(&cli.List{Split: true}, rel, "`LIST` of packages for the "+rel+" relation, separated by commas; repeatable")
			}
			fs.Var(&cli.List{}, "file", "add file `SRC:DST[:MODE]`; DST is absolute, MODE octal (0644, 0755 for executables); repeatable")
			fs.Var(&cli.List{}, "dir", "add an empty directory `DST[:MODE]`; repeatable")
			fs.Var(&cli.List{}, "symlink", "add a symbolic link `DST:TARGET`; repeatable")
			fs.Var(&cli.List{}, "conffile", "mark the file `DST` as configuration that dpkg keeps on upgrades; repeatable")
			fs.String("preinst", "", "maintainer script `FILE` run before installation")
			fs.String("postinst", "", "maintainer script `FILE` run after installation")
			fs.String("prerm", "", "maintainer script `FILE` run before removal")
			fs.String("postrm", "", "maintainer script `FILE` run after removal")
			fs.Var(&cli.List{}, "field", "add another control field `KEY:VALUE`; repeatable")
			fs.Int64("epoch", 0, "time stamp of every file in the package in Unix `SECONDS`; without it and SOURCE_DATE_EPOCH, now")
			fs.Bool("no-arch-check", false, "do not check that ELF programs fit the architecture")
			fs.String("out", ".", "write the packages into `DIR`")
			outputFlags(fs, true)
		},
		Env: map[string]string{
			"maintainer": "WDYAPT_MAINTAINER",
			"epoch":      "SOURCE_DATE_EPOCH",
		},
		Run: runDebBuild,
	}
}

func debInfoCommand() *cli.Command {
	return &cli.Command{
		Name:    "info",
		Args:    "FILE...",
		Summary: "Show what Debian packages contain",
		Description: `Shows for every FILE, a Debian binary package, its control fields, conffiles, maintainer scripts, the list of files with mode, size and link target, and the size, SHA256 and file name the package would have in the pool of a repository.

Packages whose data is compressed with xz or zstd are shown without the list of files.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("json", false, "write the result as one JSON document to standard output")
		},
		Run: runDebInfo,
	}
}

// runDebBuild builds the packages from manifest and options.
func runDebBuild(_ context.Context, inv *cli.Invocation) error {
	if len(inv.Args) > 0 {
		return inv.Usagef("unexpected argument %q; describe files with --file", inv.Args[0])
	}
	m := &deb.Manifest{}
	if name := inv.String("manifest"); name != "" {
		var err error
		if m, err = deb.LoadManifest(name); err != nil {
			return err
		}
	}
	if err := applyBuildFlags(inv, m); err != nil {
		return err
	}
	var epoch time.Time
	if inv.Given("epoch") {
		epoch = time.Unix(inv.Flags.Lookup("epoch").Value.(flag.Getter).Get().(int64), 0)
	} else {
		epoch = time.Now()
		inv.Say("No --epoch and no SOURCE_DATE_EPOCH: the files get the current time, so the packages are not reproducible.")
	}
	pkgs, err := deb.Build(m, epoch, deb.Options{NoArchCheck: inv.Bool("no-arch-check"), Warn: inv.Warn})
	if err != nil {
		return err
	}
	type built struct {
		Path         string `json:"path"`
		Package      string `json:"package"`
		Version      string `json:"version"`
		Architecture string `json:"architecture"`
		Size         int64  `json:"size"`
		SHA256       string `json:"sha256"`
		Unchanged    bool   `json:"unchanged"`
	}
	var result []built
	for _, p := range pkgs {
		name, unchanged, err := deb.WriteFile(inv.String("out"), p)
		if err != nil {
			return err
		}
		size, sum := p.Sum()
		if unchanged {
			inv.Say("%s is unchanged", name)
		} else {
			inv.Say("Wrote %s (%s)", name, humanSize(size))
		}
		result = append(result, built{Path: name, Package: p.Name, Version: p.Version, Architecture: p.Arch, Size: size, SHA256: sum, Unchanged: unchanged})
	}
	if inv.Bool("json") {
		return inv.JSON(map[string]any{"packages": result})
	}
	for _, r := range result {
		fmt.Fprintln(inv.Stdout, r.Path)
	}
	return nil
}

// applyBuildFlags transfers the given options into the manifest; they
// replace what it says. Relative paths are resolved from the working
// directory.
func applyBuildFlags(inv *cli.Invocation, m *deb.Manifest) error {
	str := func(name string, dst *string) {
		if inv.Given(name) {
			*dst = inv.String(name)
		}
	}
	list := func(name string) ([]string, bool) {
		if !inv.Given(name) {
			return nil, false
		}
		return inv.Flags.Lookup(name).Value.(*cli.List).Values, true
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		a, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		return a
	}
	str("name", &m.Package)
	str("version", &m.Version)
	str("maintainer", &m.Maintainer)
	str("summary", &m.Summary)
	str("description", &m.Description)
	str("homepage", &m.Homepage)
	str("section", &m.Section)
	str("priority", &m.Priority)
	if name := inv.String("description-file"); name != "" {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		m.Description = string(data)
	}
	if v, ok := list("arch"); ok {
		m.Architectures = v
	}
	for name, dst := range map[string]*[]string{
		"depends": &m.Depends, "pre-depends": &m.PreDepends, "recommends": &m.Recommends, "suggests": &m.Suggests,
		"conflicts": &m.Conflicts, "breaks": &m.Breaks, "replaces": &m.Replaces, "provides": &m.Provides,
		"conffile": &m.Conffiles,
	} {
		if v, ok := list(name); ok {
			*dst = v
		}
	}
	if v, ok := list("file"); ok {
		m.Files = nil
		for _, spec := range v {
			f, err := parseFileFlag(spec)
			if err != nil {
				return inv.Usagef("--file %s: %v", spec, err)
			}
			f.Src = abs(f.Src)
			if strings.HasSuffix(spec, "/") || strings.Contains(spec, "/:") {
				f.Src += "/"
			}
			m.Files = append(m.Files, f)
		}
	}
	if v, ok := list("dir"); ok {
		m.Directories = nil
		for _, spec := range v {
			p, mode, _ := strings.Cut(spec, ":")
			m.Directories = append(m.Directories, deb.Directory{Path: p, Mode: mode})
		}
	}
	if v, ok := list("symlink"); ok {
		m.Symlinks = nil
		for _, spec := range v {
			p, target, ok := strings.Cut(spec, ":")
			if !ok {
				return inv.Usagef("--symlink %s: use DST:TARGET", spec)
			}
			m.Symlinks = append(m.Symlinks, deb.Symlink{Path: p, Target: target})
		}
	}
	if v, ok := list("field"); ok {
		m.Fields = map[string]string{}
		for _, spec := range v {
			k, val, ok := strings.Cut(spec, ":")
			if !ok {
				return inv.Usagef("--field %s: use KEY:VALUE", spec)
			}
			m.Fields[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	for name, dst := range map[string]*string{"preinst": &m.Scripts.Preinst, "postinst": &m.Scripts.Postinst, "prerm": &m.Scripts.Prerm, "postrm": &m.Scripts.Postrm} {
		if inv.Given(name) {
			*dst = abs(inv.String(name))
		}
	}
	return nil
}

var octalMode = regexp.MustCompile(`^0?[0-7]{3,4}$`)

// parseFileFlag reads SRC:DST[:MODE]. DST starts with "/"; MODE is octal.
func parseFileFlag(spec string) (deb.File, error) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 {
		return deb.File{}, fmt.Errorf("use SRC:DST[:MODE]")
	}
	var f deb.File
	if len(parts) >= 3 && octalMode.MatchString(parts[len(parts)-1]) {
		f.Mode = parts[len(parts)-1]
		parts = parts[:len(parts)-1]
	}
	f.Dst = parts[len(parts)-1]
	f.Src = strings.Join(parts[:len(parts)-1], ":")
	if f.Src == "" {
		return deb.File{}, fmt.Errorf("the source is empty")
	}
	return f, nil
}

// runDebInfo shows what packages contain.
func runDebInfo(_ context.Context, inv *cli.Invocation) error {
	if len(inv.Args) == 0 {
		return inv.Usagef("name at least one package FILE")
	}
	type fileInfo struct {
		File         string            `json:"file"`
		Control      map[string]string `json:"control"`
		ControlOrder []string          `json:"control_order"`
		Conffiles    []string          `json:"conffiles"`
		Scripts      []string          `json:"scripts"`
		Files        []deb.FileInfo    `json:"files"`
		FilesNote    string            `json:"files_note,omitempty"`
		Size         int64             `json:"size"`
		MD5          string            `json:"md5"`
		SHA256       string            `json:"sha256"`
		PoolPath     string            `json:"pool_path"`
	}
	var all []fileInfo
	for i, name := range inv.Args {
		info, err := deb.ReadFile(name, true)
		if err != nil {
			return err
		}
		fi := fileInfo{File: name, Control: map[string]string{}, Conffiles: info.Conffiles, Scripts: info.Scripts, Files: info.Files, FilesNote: info.FilesNote,
			Size: info.Size, MD5: info.MD5, SHA256: info.SHA256, PoolPath: info.PoolPath("main")}
		for _, f := range info.Control {
			fi.Control[f.Key] = f.Value
			fi.ControlOrder = append(fi.ControlOrder, f.Key)
		}
		if fi.Conffiles == nil {
			fi.Conffiles = []string{}
		}
		if fi.Scripts == nil {
			fi.Scripts = []string{}
		}
		all = append(all, fi)
		if inv.Bool("json") {
			continue
		}
		w := inv.Stdout
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "File: %s\n\n%s\n", name, info.Control.String())
		fmt.Fprintf(w, "Conffiles:\n")
		for _, c := range info.Conffiles {
			fmt.Fprintf(w, "  %s\n", c)
		}
		fmt.Fprintf(w, "Maintainer scripts: %s\n", strings.Join(info.Scripts, ", "))
		fmt.Fprintf(w, "Files:\n")
		if info.FilesNote != "" {
			fmt.Fprintf(w, "  (%s)\n", info.FilesNote)
		}
		for _, f := range info.Files {
			line := fmt.Sprintf("  %s %10d %s", modeString(f), f.Size, f.Path)
			if f.Link != "" {
				line += " -> " + f.Link
			}
			fmt.Fprintln(w, line)
		}
		fmt.Fprintf(w, "Size: %d\nMD5sum: %s\nSHA256: %s\nPool path (component main): %s\n", info.Size, info.MD5, info.SHA256, fi.PoolPath)
	}
	if inv.Bool("json") {
		return inv.JSON(map[string]any{"packages": all})
	}
	return nil
}

// modeString writes type and mode like ls -l.
func modeString(f deb.FileInfo) string {
	kind := map[string]string{"dir": "d", "symlink": "l", "file": "-", "hardlink": "h"}[f.Type]
	if kind == "" {
		kind = "?"
	}
	const rwx = "rwxrwxrwx"
	b := []byte(kind)
	for i := 0; i < 9; i++ {
		if f.Mode&(1<<(8-i)) != 0 {
			b = append(b, rwx[i])
		} else {
			b = append(b, '-')
		}
	}
	return string(b)
}

// humanSize writes a size in readable form, such as "12.3 MB".
func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
