package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/worldiety/wdyapt/internal/ssh"
)

// Report is the result of Check.
type Report struct {
	Storage       string   `json:"storage"`
	HostKey       string   `json:"host_key,omitempty"`
	Algorithms    string   `json:"algorithms,omitempty"`
	Login         string   `json:"login,omitempty"`
	SFTPVersion   uint32   `json:"sftp_version,omitempty"`
	Extensions    []string `json:"sftp_extensions,omitempty"`
	AtomicReplace bool     `json:"atomic_replace"`
	Root          string   `json:"root"`
	RootExists    bool     `json:"root_exists"`
	Suites        []string `json:"suites"`
	Lock          string   `json:"lock,omitempty"`
	WriteTest     string   `json:"write_test,omitempty"`
}

// Check checks the access to st without changing anything: host key,
// login, SFTP version and extensions, root, found suites and a lock. With
// writeTest it creates a probe file and removes it again (R-ACCESS-CHECK).
func Check(ctx context.Context, st Store, writeTest bool) (*Report, error) {
	rep := &Report{Storage: st.Describe(), Suites: []string{}, AtomicReplace: true}
	if s, ok := st.(*SFTP); ok {
		c := s.Client()
		rep.HostKey = c.HostKey.Type() + " " + ssh.Fingerprint(c.HostKey)
		rep.Algorithms = c.Algorithms.String()
		rep.Login = c.AuthMethod
		sc := s.SFTPClient()
		rep.SFTPVersion = sc.Version
		for name := range sc.Extensions {
			rep.Extensions = append(rep.Extensions, name)
		}
		slices.Sort(rep.Extensions)
		rep.AtomicReplace = slices.Contains(rep.Extensions, "posix-rename@openssh.com")
		rep.Root = s.Root()
		if real, err := sc.RealPath(s.Root()); err == nil {
			rep.Root = real
		}
	} else if d, ok := st.(*Dir); ok {
		rep.Root = d.root
	}
	fi, err := st.Stat(ctx, ".")
	switch {
	case err == nil && fi.IsDir():
		rep.RootExists = true
	case err == nil:
		return nil, fmt.Errorf("%s is not a directory", rep.Root)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	if rep.RootExists {
		entries, err := st.ReadDir(ctx, "dists")
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				rep.Suites = append(rep.Suites, e.Name())
			}
		}
		slices.Sort(rep.Suites)
		if data, err := st.ReadFile(ctx, ".wdyapt.lock"); err == nil {
			rep.Lock = strings.TrimSpace(string(data))
		}
	}
	if writeTest {
		if !rep.RootExists {
			return rep, fmt.Errorf("%s does not exist; publish --create creates it", rep.Root)
		}
		tmp, err := st.WriteTemp(ctx, ".wdyapt-check", bytes.NewReader([]byte("wdyapt write test\n")))
		if err != nil {
			return rep, fmt.Errorf("write test: %w", err)
		}
		if err := st.Remove(ctx, tmp); err != nil {
			return rep, fmt.Errorf("write test: removing %s: %w", tmp, err)
		}
		rep.WriteTest = "created and removed " + tmp
	}
	return rep, nil
}
