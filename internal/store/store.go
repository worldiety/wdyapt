// Package store is the storage that holds a repository: an SFTP server, a
// local directory or, read-only, an HTTP server. The publication needs only
// what Store describes; all names are relative to the root of the
// repository and separated by "/".
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

// Reader reads from a storage.
type Reader interface {
	// ReadFile reads a whole file; fs.ErrNotExist if it is missing.
	ReadFile(ctx context.Context, name string) ([]byte, error)
	// Open reads a large file as a stream.
	Open(ctx context.Context, name string) (io.ReadCloser, error)
	Stat(ctx context.Context, name string) (fs.FileInfo, error)
	// ReadDir lists a directory; ErrNoListing if the storage cannot do
	// that.
	ReadDir(ctx context.Context, dir string) ([]fs.DirEntry, error)
	// Describe names the storage for messages, without secrets.
	Describe() string
	Close() error
}

// Store reads and writes.
type Store interface {
	Reader
	MkdirAll(ctx context.Context, dir string) error
	// WriteTemp writes r under a new temporary name next to name
	// (name + ".wdyapt-<run>.tmp"), syncs if possible and returns the
	// name.
	WriteTemp(ctx context.Context, name string, r io.Reader) (string, error)
	// Rename atomically replaces to with from.
	Rename(ctx context.Context, from, to string) error
	// CreateExclusive creates name with data and fails with fs.ErrExist if
	// it exists.
	CreateExclusive(ctx context.Context, name string, data []byte) error
	// Remove removes a file; only for our own temporary files and the
	// lock.
	Remove(ctx context.Context, name string) error
}

// ErrNoListing reports a storage that cannot list directories.
var ErrNoListing = errors.New("this storage cannot list directories; name the suites")

// ErrReadOnly reports a storage that can only be read.
var ErrReadOnly = errors.New("this storage is read-only")

// TempMarker is part of every temporary name that wdyapt assigns.
const TempMarker = ".wdyapt-"

// IsTemp reports whether name is a temporary name of wdyapt.
func IsTemp(name string) bool {
	base := path.Base(name)
	i := strings.LastIndex(base, TempMarker)
	return i > 0 && strings.HasSuffix(base, ".tmp")
}

// TempName builds the temporary name of name for the run run.
func TempName(name, run string) string {
	return name + TempMarker + run + ".tmp"
}

// SplitTemp returns the final name and the run for a temporary name.
func SplitTemp(name string) (final, run string, ok bool) {
	if !IsTemp(name) {
		return "", "", false
	}
	i := strings.LastIndex(name, TempMarker)
	return name[:i], strings.TrimSuffix(name[i+len(TempMarker):], ".tmp"), true
}

// NewRunID returns a random ID for a run.
func NewRunID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Clean checks a name relative to the root: no absolute path, no "..", no
// control characters. "." is the root.
func Clean(name string) (string, error) {
	if name == "" || name == "." {
		return ".", nil
	}
	if strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\x00\r\n\\") {
		return "", fmt.Errorf("invalid path %q in the repository", name)
	}
	c := path.Clean(name)
	if c != name || c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("invalid path %q in the repository", name)
	}
	return c, nil
}

// ReadLimited reads a file, at most limit bytes.
func ReadLimited(ctx context.Context, r Reader, name string, limit int64) ([]byte, error) {
	f, err := r.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return data, nil
}

// Exists reports whether name exists.
func Exists(ctx context.Context, r Reader, name string) (bool, error) {
	_, err := r.Stat(ctx, name)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, err
}
