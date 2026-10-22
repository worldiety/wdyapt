package depcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/cst"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

const (
	module  = "github.com/worldiety/wdyapt"
	allowed = "github.com/worldiety/speclink/spec"
)

// goTool returns the go program the tests run with.
func goTool(t *testing.T) string {
	t.Helper()
	if p := filepath.Join(runtime.GOROOT(), "bin", "go"); fileExists(p) {
		return p
	}
	p, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not found")
	}
	return p
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// root is the root directory of the module.
func root(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

type listedPackage struct {
	ImportPath string
	Standard   bool
	Dir        string
	GoFiles    []string
	Imports    []string
	Module     *struct{ Path string }
}

func goList(t *testing.T, args ...string) []listedPackage {
	t.Helper()
	cmd := exec.Command(goTool(t), append([]string{"list", "-json"}, args...)...)
	cmd.Dir = root(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// The program imports only the standard library, its own packages and
// speclink/spec, and go.mod requires exactly this one module.
func TestOnlyStandardLibrary(t *testing.T) {
	pkgs := goList(t, "-deps", "./cmd/wdyapt")
	if len(pkgs) < 10 {
		t.Fatalf("only %d packages listed", len(pkgs))
	}
	for _, p := range pkgs {
		switch {
		case p.Standard:
		case p.ImportPath == module || strings.HasPrefix(p.ImportPath, module+"/"):
		case p.ImportPath == allowed:
		default:
			t.Errorf("wdyapt depends on %s", p.ImportPath)
		}
	}

	data, err := os.ReadFile(filepath.Join(root(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var requires []string
	inBlock := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == ")":
			inBlock = false
		case line == "require (":
			inBlock = true
		case strings.HasPrefix(line, "require "):
			requires = append(requires, strings.Fields(strings.TrimPrefix(line, "require "))[0])
		case inBlock && line != "" && !strings.HasPrefix(line, "//"):
			requires = append(requires, strings.Fields(line)[0])
		case strings.HasPrefix(line, "tool ") || strings.HasPrefix(line, "replace "):
			t.Errorf("go.mod has %q", line)
		}
	}
	if len(requires) != 1 || requires[0] != allowed {
		t.Errorf("go.mod requires %v, want only %s", requires, allowed)
	}
	spec.Verified(t, cst.RCstStandardLibraryOnly)
}

// startsProcess recognizes calls that start another program.
var startsProcess = regexp.MustCompile(`\b(os\.StartProcess|syscall\.(ForkExec|Exec|StartProcess))\b`)

// No package of the module starts other programs: no os/exec, no
// os.StartProcess, no syscall.Exec outside of tests.
func TestNoExec(t *testing.T) {
	pkgs := goList(t, "./...")
	for _, p := range pkgs {
		for _, imp := range p.Imports {
			if imp == "os/exec" {
				t.Errorf("%s imports os/exec", p.ImportPath)
			}
		}
		for _, f := range p.GoFiles {
			data, err := os.ReadFile(filepath.Join(p.Dir, f))
			if err != nil {
				t.Fatal(err)
			}
			if m := startsProcess.Find(data); m != nil {
				t.Errorf("%s/%s calls %s", p.ImportPath, f, m)
			}
		}
	}
	spec.Verified(t, cst.RCstNoExternalPrograms)
}

// wdyapt builds without CGO for Linux and macOS on amd64 and arm64.
func TestBuildsWithoutCgo(t *testing.T) {
	if testing.Short() {
		t.Skip("cross builds take a while")
	}
	out := t.TempDir()
	for _, goos := range []string{"linux", "darwin"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			cmd := exec.Command(goTool(t), "build", "-o", filepath.Join(out, goos+"_"+goarch), "./cmd/wdyapt")
			cmd.Dir = root(t)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s/%s: %v\n%s", goos, goarch, err, b)
			}
		}
	}
	spec.Verified(t, cst.RCstStandardLibraryOnly, nfr.RNfrPlatforms)
}
