package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/worldiety/wdyapt/internal/sftp"
	"github.com/worldiety/wdyapt/internal/ssh"
)

// SFTPOptions describe the access to an SFTP storage. Credentials live only
// in Auth and appear in no message.
type SFTPOptions struct {
	Remote  Remote
	Auth    []ssh.AuthMethod
	HostKey ssh.HostKeyCallback
	// HostKeyAlgorithms orders the algorithms, for example those from
	// known_hosts first.
	HostKeyAlgorithms []string
	Version           string
	// Logf records protocol details (--verbose), Warn warnings.
	Logf func(format string, args ...any)
	Warn func(format string, args ...any)
}

// SFTP is a repository on an SFTP server.
type SFTP struct {
	remote Remote
	ssh    *ssh.Client
	ch     io.Closer
	c      *sftp.Client
	root   string
	run    string
	once   sync.Once
}

// OpenSFTP connects, verifies the host key, logs in and starts the sftp
// subsystem. The root is the path from the address, "~/…" relative to the
// login directory.
func OpenSFTP(ctx context.Context, opts SFTPOptions) (*SFTP, error) {
	r := opts.Remote
	cfg := &ssh.ClientConfig{
		Config: ssh.Config{HostKeyAlgorithms: opts.HostKeyAlgorithms, Version: "wdyapt_" + strings.ReplaceAll(opts.Version, " ", "_"), Logf: opts.Logf},
		User:   r.User, Auth: opts.Auth, HostKey: opts.HostKey,
		Banner: func(text string) {
			if opts.Logf != nil {
				opts.Logf("Server banner: %s", strings.TrimSpace(text))
			}
		},
		Stderr: func(text string) {
			if opts.Logf != nil {
				opts.Logf("Server: %s", strings.TrimSpace(text))
			}
		},
	}
	client, err := ssh.Dial(ctx, r.Address(), cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r, err)
	}
	ch, err := client.Subsystem(ctx, "sftp")
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("%s: %w", r, err)
	}
	c, err := sftp.NewClient(ch)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("%s: %w", r, err)
	}
	c.Warn = opts.Warn
	s := &SFTP{remote: r, ssh: client, ch: ch, c: c, run: NewRunID()}
	if r.Home {
		home, err := c.RealPath(".")
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("%s: finding the login directory: %w", r, err)
		}
		s.root = path.Join(home, r.Path)
	} else {
		s.root = path.Clean(r.Path)
	}
	return s, nil
}

// Client is the SSH connection, for messages about algorithms and login.
func (s *SFTP) Client() *ssh.Client { return s.ssh }

// SFTPClient is the SFTP session.
func (s *SFTP) SFTPClient() *sftp.Client { return s.c }

// Root is the root of the repository on the server.
func (s *SFTP) Root() string { return s.root }

func (s *SFTP) path(name string) (string, error) {
	c, err := Clean(name)
	if err != nil {
		return "", err
	}
	return path.Join(s.root, c), nil
}

func (s *SFTP) Describe() string { return s.remote.String() }

func (s *SFTP) Close() error {
	var err error
	s.once.Do(func() {
		s.c.Close()
		err = s.ssh.Close()
	})
	return err
}

func (s *SFTP) ReadFile(ctx context.Context, name string) ([]byte, error) {
	f, err := s.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (s *SFTP) Open(_ context.Context, name string) (io.ReadCloser, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	return s.c.Open(p)
}

func (s *SFTP) Stat(_ context.Context, name string) (fs.FileInfo, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	return s.c.Stat(p)
}

func (s *SFTP) ReadDir(_ context.Context, dir string) ([]fs.DirEntry, error) {
	p, err := s.path(dir)
	if err != nil {
		return nil, err
	}
	return s.c.ReadDir(p)
}

func (s *SFTP) MkdirAll(_ context.Context, dir string) error {
	p, err := s.path(dir)
	if err != nil {
		return err
	}
	return s.c.MkdirAll(p)
}

func (s *SFTP) WriteTemp(ctx context.Context, name string, r io.Reader) (string, error) {
	tmp := TempName(name, s.run)
	p, err := s.path(tmp)
	if err != nil {
		return "", err
	}
	f, err := s.c.CreateExclusive(p, 0o644)
	if err != nil {
		return "", err
	}
	_, err = f.ReadFrom(&ctxReader{ctx: ctx, r: r})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		s.c.Remove(p)
		return "", fmt.Errorf("writing %s: %w", tmp, err)
	}
	return tmp, nil
}

func (s *SFTP) Rename(_ context.Context, from, to string) error {
	pf, err := s.path(from)
	if err != nil {
		return err
	}
	pt, err := s.path(to)
	if err != nil {
		return err
	}
	return s.c.Rename(pf, pt)
}

func (s *SFTP) CreateExclusive(_ context.Context, name string, data []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	f, err := s.c.CreateExclusive(p, 0o644)
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
		s.c.Remove(p)
	}
	return err
}

func (s *SFTP) Remove(_ context.Context, name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	return s.c.Remove(p)
}
