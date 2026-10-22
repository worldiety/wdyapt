package store

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// Kinds of target in --remote.
const (
	KindDir  = "dir"
	KindSFTP = "sftp"
	KindHTTP = "http"
)

// Remote is a parsed --remote.
type Remote struct {
	Kind string
	// Dir is the local directory (KindDir), URL the base (KindHTTP).
	Dir string
	URL string
	// User, Host and Port apply to SFTP; Path is the path on the server,
	// relative to the login directory if Home is set.
	User string
	Host string
	Port int
	Path string
	Home bool
}

// Address is host:port.
func (r Remote) Address() string { return net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) }

// String names the target without secrets.
func (r Remote) String() string {
	switch r.Kind {
	case KindSFTP:
		p := r.Path
		if r.Home {
			p = "~/" + p
		}
		return fmt.Sprintf("sftp://%s@%s/%s", url.PathEscape(r.User), r.Address(), strings.TrimPrefix(p, "/"))
	case KindHTTP:
		return r.URL
	}
	return r.Dir
}

// ParseRemote parses --remote: sftp://USER@HOST[:PORT]/PATH (with /~/PATH
// relative to the login directory), file:///PATH, http(s)://… or a local
// directory. A password in the address is rejected.
func ParseRemote(s string) (Remote, error) {
	if s == "" {
		return Remote{}, errors.New("no repository given (--remote or WDYAPT_REMOTE)")
	}
	if !strings.Contains(s, "://") {
		return Remote{Kind: KindDir, Dir: filepath.Clean(s)}, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return Remote{}, fmt.Errorf("invalid --remote: %v", err)
	}
	if _, has := u.User.Password(); has {
		return Remote{}, errors.New("--remote contains a password; put it into WDYAPT_SFTP_PASSWORD or a file named by --password-file instead")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return Remote{}, errors.New("--remote must not have a query or fragment")
	}
	switch u.Scheme {
	case "file":
		if u.Host != "" && u.Host != "localhost" {
			return Remote{}, errors.New("file:// URLs must name a local path, file:///PATH")
		}
		return Remote{Kind: KindDir, Dir: filepath.Clean(u.Path)}, nil
	case "http", "https":
		return Remote{Kind: KindHTTP, URL: s}, nil
	case "sftp":
		r := Remote{Kind: KindSFTP, User: u.User.Username(), Host: u.Hostname(), Port: 22}
		if u.User == nil || r.User == "" {
			return Remote{}, errors.New("--remote needs a user: sftp://USER@HOST/PATH")
		}
		if r.Host == "" {
			return Remote{}, errors.New("--remote needs a host: sftp://USER@HOST/PATH")
		}
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return Remote{}, fmt.Errorf("invalid port %q in --remote", p)
			}
			r.Port = n
		}
		p := u.Path
		switch {
		case p == "/~" || strings.HasPrefix(p, "/~/"):
			r.Home, r.Path = true, strings.Trim(strings.TrimPrefix(p, "/~"), "/")
		case p == "" || p == "/":
			return Remote{}, errors.New("--remote needs a path: sftp://USER@HOST/PATH or sftp://USER@HOST/~/PATH")
		default:
			r.Path = p
		}
		if strings.Contains("/"+r.Path+"/", "/../") {
			return Remote{}, errors.New("--remote must not contain \"..\"")
		}
		return r, nil
	}
	return Remote{}, fmt.Errorf("--remote with scheme %q: use sftp://, file:// or a directory, for reading also https://", u.Scheme)
}
