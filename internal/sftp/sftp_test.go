package sftp_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/sftp"
	"github.com/worldiety/wdyapt/internal/sftp/sftptest"
	"github.com/worldiety/wdyapt/requirements/dec"
)

func start(t *testing.T, opts sftptest.Options) (*sftp.Client, *sftptest.Server) {
	t.Helper()
	srv, err := sftptest.New(t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	go srv.Serve(b)
	c, err := sftp.NewClient(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); b.Close() })
	return c, srv
}

// All operations that wdyapt uses, against the test server.
func TestSFTPOperations(t *testing.T) {
	c, srv := start(t, sftptest.Options{})
	if c.Version != 3 || !c.HasExtension(sftp.ExtPosixRename) || !c.HasExtension(sftp.ExtFsync) {
		t.Fatalf("version %d, extensions %v", c.Version, c.Extensions)
	}
	if r, w := c.Limits(); r != 64<<10 || w != 64<<10 {
		t.Errorf("limits %d %d", r, w)
	}
	home, err := c.RealPath(".")
	if err != nil || home != sftptest.Home {
		t.Fatalf("realpath: %q %v", home, err)
	}
	if err := c.MkdirAll("repo/dists/stable"); err != nil {
		t.Fatal(err)
	}
	if fi, err := c.Stat("/home/user/repo/dists"); err != nil || !fi.IsDir() {
		t.Fatalf("stat dir: %v", err)
	}
	if _, err := c.Stat("repo/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}

	// Large writes and reads with many requests in flight.
	data := make([]byte, 5<<20+12345)
	rand.Read(data)
	f, err := c.CreateExclusive("repo/big.tmp", 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.ReadFrom(bytes.NewReader(data)); err != nil || n != int64(len(data)) {
		t.Fatalf("write: %d %v", n, err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := c.CreateExclusive("repo/big.tmp", 0o644); !errors.Is(err, fs.ErrExist) {
		t.Errorf("exclusive create of an existing file: %v", err)
	}
	if err := c.Rename("repo/big.tmp", "repo/big"); err != nil {
		t.Fatal(err)
	}
	r, err := c.Open("repo/big")
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if _, err := io.Copy(&got, r); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("read back %d bytes, want %d", got.Len(), len(data))
	}
	onDisk, _ := os.ReadFile(filepath.Join(srv.Root, "home/user/repo/big"))
	if !bytes.Equal(onDisk, data) {
		t.Error("file on the server differs")
	}

	// posix-rename replaces.
	w, _ := c.OpenFile("repo/small", sftp.FlagWrite|sftp.FlagCreate|sftp.FlagTrunc, 0o644)
	w.Write([]byte("new"))
	w.Close()
	if err := c.Rename("repo/small", "repo/big"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(srv.Root, "home/user/repo/big")); string(b) != "new" {
		t.Errorf("replaced content %q", b)
	}
	entries, err := c.ReadDir("repo")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if err != nil || strings.Join(names, " ") != "big dists" {
		t.Errorf("readdir: %v %v", names, err)
	}
	if err := c.Remove("repo/big"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stat("/home/user/repo/big"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("after remove: %v", err)
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// Without posix-rename, Rename replaces via REMOVE and RENAME, with a
// warning.
func TestRenameWithoutPosixRename(t *testing.T) {
	c, _ := start(t, sftptest.Options{NoPosixRename: true, NoFsync: true})
	var warned []string
	c.Warn = func(f string, a ...any) { warned = append(warned, f) }
	for _, name := range []string{"a", "b"} {
		f, err := c.OpenFile(name, sftp.FlagWrite|sftp.FlagCreate, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(name))
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	if err := c.Rename("a", "b"); err != nil {
		t.Fatal(err)
	}
	r, _ := c.Open("b")
	b, _ := io.ReadAll(r)
	if string(b) != "a" || len(warned) != 1 || !strings.Contains(warned[0], "atomically") {
		t.Errorf("content %q, warnings %v", b, warned)
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}
