//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDpkgAcceptsPackages: dpkg-deb reads a package from wdyapt, dpkg
// installs it with files, modes, symlink, conffile and maintainer scripts,
// removes it and with --purge also deletes the conffile. The program in
// the package is wdyapt itself, a real ELF program of this architecture.
func TestDpkgAcceptsPackages(t *testing.T) {
	dir := t.TempDir()
	a := arch(t)
	writeFile(t, filepath.Join(dir, "hello.conf"), "greeting=hello\n", 0o644)
	writeFile(t, filepath.Join(dir, "postinst"), "#!/bin/sh\nset -e\nmkdir -p /var/lib/e2e-dpkg\necho installed > /var/lib/e2e-dpkg/marker\n", 0o755)
	writeFile(t, filepath.Join(dir, "postrm"), "#!/bin/sh\nset -e\nif [ \"$1\" = purge ]; then rm -rf /var/lib/e2e-dpkg; fi\n", 0o755)
	r := must(t, nil, "deb", "build", "--name", "e2e-dpkg", "--version", "1.2.3-1", "--arch", a,
		"--maintainer", "E2E <e2e@example.com>", "--summary", "dpkg acceptance", "--description", "Checks that dpkg accepts packages built by wdyapt.",
		"--file", wdyaptBin+":/usr/bin/e2e-dpkg:0755",
		"--file", filepath.Join(dir, "hello.conf")+":/etc/e2e-dpkg/hello.conf:0640",
		"--dir", "/var/cache/e2e-dpkg:0750",
		"--symlink", "/usr/sbin/e2e-dpkg:/usr/bin/e2e-dpkg",
		"--conffile", "/etc/e2e-dpkg/hello.conf",
		"--postinst", filepath.Join(dir, "postinst"), "--postrm", filepath.Join(dir, "postrm"),
		"--epoch", "1791000000", "--out", dir)
	deb := strings.TrimSpace(r.stdout)

	info := sh(t, "dpkg-deb", "--info", deb)
	for _, want := range []string{"Package: e2e-dpkg", "Version: 1.2.3-1", "Architecture: " + a, "postinst", "postrm", "conffiles"} {
		if !strings.Contains(info, want) {
			t.Errorf("dpkg-deb --info lacks %q:\n%s", want, info)
		}
	}
	contents := sh(t, "dpkg-deb", "--contents", deb)
	for _, want := range []string{"-rwxr-xr-x root/root", "./usr/bin/e2e-dpkg", "-rw-r----- root/root", "./etc/e2e-dpkg/hello.conf", "drwxr-x--- root/root", "./var/cache/e2e-dpkg/", "./usr/sbin/e2e-dpkg -> /usr/bin/e2e-dpkg"} {
		if !strings.Contains(contents, want) {
			t.Errorf("dpkg-deb --contents lacks %q:\n%s", want, contents)
		}
	}

	sh(t, "dpkg", "-i", deb)
	if out := sh(t, "/usr/sbin/e2e-dpkg", "version"); !strings.HasPrefix(out, "wdyapt ") {
		t.Errorf("installed program says %q", out)
	}
	if fi, err := os.Stat("/etc/e2e-dpkg/hello.conf"); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("conffile: %v %v", fi, err)
	}
	if fi, err := os.Stat("/var/cache/e2e-dpkg"); err != nil || fi.Mode().Perm() != 0o750 {
		t.Errorf("directory: %v %v", fi, err)
	}
	if readFile(t, "/var/lib/e2e-dpkg/marker") != "installed\n" {
		t.Error("postinst did not run")
	}
	if c := sh(t, "dpkg-query", "-W", "-f=${Conffiles}", "e2e-dpkg"); !strings.Contains(c, "/etc/e2e-dpkg/hello.conf") {
		t.Errorf("conffiles: %q", c)
	}
	// dpkg checks the md5sums of the installed package.
	if out, err := exec.Command("dpkg", "--verify", "e2e-dpkg").CombinedOutput(); err != nil || len(out) != 0 {
		t.Errorf("dpkg --verify: %v %s", err, out)
	}
	sh(t, "dpkg", "-r", "e2e-dpkg")
	if _, err := os.Stat("/usr/bin/e2e-dpkg"); err == nil {
		t.Error("program left after dpkg -r")
	}
	if _, err := os.Stat("/etc/e2e-dpkg/hello.conf"); err != nil {
		t.Error("dpkg -r removed the conffile")
	}
	sh(t, "dpkg", "--purge", "e2e-dpkg")
	for _, gone := range []string{"/etc/e2e-dpkg/hello.conf", "/var/lib/e2e-dpkg"} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s left after --purge", gone)
		}
	}
}
