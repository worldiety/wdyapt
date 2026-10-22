package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/ssh"
	"github.com/worldiety/wdyapt/internal/ssh/agent"
	"github.com/worldiety/wdyapt/internal/ssh/knownhosts"
	"github.com/worldiety/wdyapt/internal/store"
	"github.com/worldiety/wdyapt/internal/version"
)

// timeout returns --timeout.
func timeout(inv *cli.Invocation) time.Duration {
	f := inv.Flags.Lookup("timeout")
	if f == nil {
		return 0
	}
	return f.Value.(flag.Getter).Get().(time.Duration)
}

// openReader opens --remote for reading: directory, HTTP or SFTP.
func openReader(ctx context.Context, inv *cli.Invocation) (store.Reader, error) {
	r, err := store.ParseRemote(inv.String("remote"))
	if err != nil {
		return nil, inv.Usagef("%v", err)
	}
	switch r.Kind {
	case store.KindHTTP:
		return store.OpenHTTP(r.URL, max(timeout(inv), time.Minute)), nil
	case store.KindDir:
		return store.OpenDir(r.Dir)
	}
	return openSFTP(ctx, inv, r)
}

// openStore opens --remote for writing: directory or SFTP.
func openStore(ctx context.Context, inv *cli.Invocation) (store.Store, error) {
	r, err := store.ParseRemote(inv.String("remote"))
	if err != nil {
		return nil, inv.Usagef("%v", err)
	}
	switch r.Kind {
	case store.KindHTTP:
		return nil, inv.Usagef("%s is read-only; publish needs sftp:// or a directory", r.URL)
	case store.KindDir:
		return store.OpenDir(r.Dir)
	}
	return openSFTP(ctx, inv, r)
}

// openSFTP connects to an SFTP storage: host key from --host-key or
// known_hosts, login with key file, ssh-agent, password and
// keyboard-interactive, each when something is there for it.
func openSFTP(ctx context.Context, inv *cli.Invocation, r store.Remote) (*store.SFTP, error) {
	addr := r.Address()
	hostKey, preferred, err := hostKeyCheck(inv, addr)
	if err != nil {
		return nil, err
	}
	var auth []ssh.AuthMethod
	if name := inv.String("identity"); name != "" {
		data, err := os.ReadFile(expandHome(name))
		if err != nil {
			return nil, err
		}
		if info, err := os.Stat(expandHome(name)); err == nil && info.Mode().Perm()&0o077 != 0 {
			inv.Warn("%s can be read by other users; restrict it with chmod 600", name)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		auth = append(auth, ssh.PublicKeys("identity file "+name, signer))
	}
	if sock := inv.Getenv("SSH_AUTH_SOCK"); sock != "" && !inv.Bool("no-agent") {
		if ag, err := agent.Dial(sock); err != nil {
			inv.Verbose("ssh-agent at SSH_AUTH_SOCK not usable: %v", err)
		} else {
			// The agent is only needed for the login.
			defer ag.Close()
			if signers, err := ag.Signers(); err != nil {
				inv.Verbose("ssh-agent: %v", err)
			} else if len(signers) > 0 {
				auth = append(auth, ssh.PublicKeys("ssh-agent", signers...))
			}
		}
	}
	password, err := secretFrom(inv, "WDYAPT_SFTP_PASSWORD", "password-file")
	if err != nil {
		return nil, err
	}
	if len(password) > 0 {
		auth = append(auth, ssh.Password(password), ssh.KeyboardInteractive(password))
	}
	if len(auth) == 0 {
		return nil, inv.Usagef("no credentials for %s: set WDYAPT_SFTP_PASSWORD, --password-file, --identity or run an ssh-agent", r)
	}
	inv.Say("Connecting to %s", r)
	st, err := store.OpenSFTP(ctx, store.SFTPOptions{
		Remote: r, Auth: auth, HostKey: hostKey, HostKeyAlgorithms: preferred,
		Version: version.String(), Logf: inv.Verbose, Warn: inv.Warn,
	})
	if err != nil {
		return nil, err
	}
	c := st.Client()
	inv.Verbose("Negotiated %s", c.Algorithms)
	inv.Say("Logged in as %s with %s", r.User, c.AuthMethod)
	sc := st.SFTPClient()
	var exts []string
	for name := range sc.Extensions {
		exts = append(exts, name)
	}
	slices.Sort(exts)
	inv.Verbose("SFTP version %d, extensions %s", sc.Version, strings.Join(exts, ", "))
	return st, nil
}

// hostKeyCheck returns the host key check and the preferred algorithms:
// with --host-key the fingerprints, otherwise known_hosts.
func hostKeyCheck(inv *cli.Invocation, addr string) (ssh.HostKeyCallback, []string, error) {
	if fps := inv.String("host-key"); fps != "" {
		var list []string
		for _, f := range strings.Split(fps, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !strings.HasPrefix(f, "SHA256:") {
					return nil, nil, inv.Usagef("--host-key %q: give SHA256 fingerprints as \"wdyapt remote hostkey\" prints them", f)
				}
				list = append(list, f)
			}
		}
		check := knownhosts.Fingerprints(list)
		return func(a string, key ssh.PublicKey) error {
			if err := check(a, key); err != nil {
				return err
			}
			inv.Say("Host key %s matches --host-key", ssh.Fingerprint(key))
			return nil
		}, nil, nil
	}
	name := expandHome(inv.String("known-hosts"))
	db, err := knownhosts.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("the known_hosts file %s does not exist; fetch the host keys with \"wdyapt remote hostkey\", check them over a second channel, and name the file with --known-hosts, or give --host-key", name)
	}
	if err != nil {
		return nil, nil, err
	}
	for _, n := range db.Notes {
		inv.Verbose("%s", n)
	}
	// Algorithms for which known_hosts knows a key go to the front.
	var preferred []string
	all := []string{ssh.KeyEd25519, ssh.KeyECDSA256, ssh.KeyECDSA384, ssh.KeyECDSA521, ssh.SigRSASHA512, ssh.SigRSASHA256}
	known := db.KnownTypes(addr)
	for _, a := range all {
		typ := a
		if a == ssh.SigRSASHA512 || a == ssh.SigRSASHA256 {
			typ = ssh.KeyRSA
		}
		if slices.Contains(known, typ) {
			preferred = append(preferred, a)
		}
	}
	for _, a := range all {
		if !slices.Contains(preferred, a) {
			preferred = append(preferred, a)
		}
	}
	return db.Callback(func(l *knownhosts.Line) {
		inv.Say("Host key %s %s matches %s line %d", l.Key.Type(), ssh.Fingerprint(l.Key), l.File, l.Number)
	}), preferred, nil
}

// expandHome replaces a leading "~/" with the home directory.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
