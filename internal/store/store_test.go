package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRemote(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Remote
	}{
		{"sftp://deploy@sftp.example.com:2222/~/debian-repository", Remote{Kind: KindSFTP, User: "deploy", Host: "sftp.example.com", Port: 2222, Path: "debian-repository", Home: true}},
		{"sftp://us%40er@host/srv/repo", Remote{Kind: KindSFTP, User: "us@er", Host: "host", Port: 22, Path: "/srv/repo"}},
		{"sftp://u@[::1]/~", Remote{Kind: KindSFTP, User: "u", Host: "::1", Port: 22, Home: true}},
		{"file:///srv/repo", Remote{Kind: KindDir, Dir: "/srv/repo"}},
		{"build/repo/", Remote{Kind: KindDir, Dir: "build/repo"}},
		{"https://deb.example.com/debian/", Remote{Kind: KindHTTP, URL: "https://deb.example.com/debian/"}},
	} {
		got, err := ParseRemote(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%s: %+v %v", tc.in, got, err)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"sftp://u:secret@host/x", "WDYAPT_SFTP_PASSWORD"},
		{"sftp://host/x", "needs a user"},
		{"sftp://u@host", "needs a path"},
		{"sftp://u@host:99999/x", "invalid port"},
		{"sftp://u@host/~/../etc", ".."},
		{"ftp://u@host/x", "scheme"},
		{"", "no repository"},
	} {
		if _, err := ParseRemote(tc.in); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.in, err)
		}
	}
	if _, err := ParseRemote("sftp://u:hunter2@host/x"); err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Error("the password appears in the error")
	}
}

func TestDirStore(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "repo")
	d, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Stat(ctx, "."); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing root: %v", err)
	}
	if err := d.MkdirAll(ctx, "dists/stable"); err != nil {
		t.Fatal(err)
	}
	tmp, err := d.WriteTemp(ctx, "dists/stable/Release", strings.NewReader("hello"))
	if err != nil || !IsTemp(tmp) {
		t.Fatalf("WriteTemp: %s %v", tmp, err)
	}
	if final, _, ok := SplitTemp(tmp); !ok || final != "dists/stable/Release" {
		t.Errorf("SplitTemp(%s) = %s", tmp, final)
	}
	if err := d.Rename(ctx, tmp, "dists/stable/Release"); err != nil {
		t.Fatal(err)
	}
	if b, _ := d.ReadFile(ctx, "dists/stable/Release"); string(b) != "hello" {
		t.Errorf("content %q", b)
	}
	if err := d.CreateExclusive(ctx, ".lock", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateExclusive(ctx, ".lock", []byte("b")); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second lock: %v", err)
	}
	for _, bad := range []string{"../x", "/etc/passwd", "a/../../b", "a\\b"} {
		if _, err := d.ReadFile(ctx, bad); err == nil || !strings.Contains(err.Error(), "invalid path") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "dists/stable")); err != nil {
		t.Error(err)
	}
}
