package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Dir is a repository in a local directory.
type Dir struct {
	root string
	run  string
}

// OpenDir opens the directory root; it need not exist, MkdirAll creates
// it.
func OpenDir(root string) (*Dir, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Dir{root: abs, run: NewRunID()}, nil
}

func (d *Dir) path(name string) (string, error) {
	c, err := Clean(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(d.root, filepath.FromSlash(c)), nil
}

func (d *Dir) Describe() string { return "directory " + d.root }
func (d *Dir) Close() error     { return nil }

func (d *Dir) ReadFile(_ context.Context, name string) ([]byte, error) {
	p, err := d.path(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (d *Dir) Open(_ context.Context, name string) (io.ReadCloser, error) {
	p, err := d.path(name)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (d *Dir) Stat(_ context.Context, name string) (fs.FileInfo, error) {
	p, err := d.path(name)
	if err != nil {
		return nil, err
	}
	return os.Stat(p)
}

func (d *Dir) ReadDir(_ context.Context, dir string) ([]fs.DirEntry, error) {
	p, err := d.path(dir)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(p)
}

func (d *Dir) MkdirAll(_ context.Context, dir string) error {
	p, err := d.path(dir)
	if err != nil {
		return err
	}
	return os.MkdirAll(p, 0o755)
}

func (d *Dir) WriteTemp(ctx context.Context, name string, r io.Reader) (string, error) {
	tmp := TempName(name, d.run)
	p, err := d.path(tmp)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(f, &ctxReader{ctx: ctx, r: r})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(p)
		return "", fmt.Errorf("writing %s: %w", tmp, err)
	}
	return tmp, nil
}

func (d *Dir) Rename(_ context.Context, from, to string) error {
	pf, err := d.path(from)
	if err != nil {
		return err
	}
	pt, err := d.path(to)
	if err != nil {
		return err
	}
	if err := os.Rename(pf, pt); err != nil {
		return err
	}
	syncDir(filepath.Dir(pt))
	return nil
}

func (d *Dir) CreateExclusive(_ context.Context, name string, data []byte) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fs.ErrExist
		}
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(p)
	}
	syncDir(filepath.Dir(p))
	return err
}

func (d *Dir) Remove(_ context.Context, name string) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// syncDir writes a directory to disk so that a rename survives a crash;
// where that is not possible, it stays an attempt.
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		f.Sync()
		f.Close()
	}
}

// ctxReader aborts reading as soon as ctx ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
