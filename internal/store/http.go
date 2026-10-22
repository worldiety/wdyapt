package store

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

// HTTP reads a published repository over HTTP or HTTPS.
type HTTP struct {
	base   string
	client *http.Client
}

// OpenHTTP reads below base.
func OpenHTTP(base string, timeout time.Duration) *HTTP {
	return &HTTP{base: strings.TrimSuffix(base, "/") + "/", client: &http.Client{Timeout: timeout}}
}

func (h *HTTP) Describe() string { return h.base }
func (h *HTTP) Close() error     { return nil }

func (h *HTTP) url(name string) (string, error) {
	c, err := Clean(name)
	if err != nil {
		return "", err
	}
	return h.base + c, nil
}

func (h *HTTP) do(ctx context.Context, method, name string) (*http.Response, error) {
	u, err := h.url(name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound, http.StatusGone:
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: %w", method, u, fs.ErrNotExist)
	}
	resp.Body.Close()
	return nil, fmt.Errorf("%s %s: %s", method, u, resp.Status)
}

func (h *HTTP) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	resp, err := h.do(ctx, http.MethodGet, name)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (h *HTTP) ReadFile(ctx context.Context, name string) ([]byte, error) {
	f, err := h.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (h *HTTP) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	resp, err := h.do(ctx, http.MethodHead, name)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return fileInfo{name: name, size: resp.ContentLength}, nil
}

func (h *HTTP) ReadDir(context.Context, string) ([]fs.DirEntry, error) {
	return nil, ErrNoListing
}

// fileInfo is what HTTP knows about a file.
type fileInfo struct {
	name string
	size int64
}

func (f fileInfo) Name() string       { return f.name }
func (f fileInfo) Size() int64        { return f.size }
func (f fileInfo) Mode() fs.FileMode  { return 0o444 }
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return false }
func (f fileInfo) Sys() any           { return nil }
