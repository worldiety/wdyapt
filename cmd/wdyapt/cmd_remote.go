package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/ssh"
	"github.com/worldiety/wdyapt/internal/ssh/knownhosts"
	"github.com/worldiety/wdyapt/internal/store"
)

// remoteCommand is the group "remote": access to the storage.
func remoteCommand() *cli.Command {
	return &cli.Command{
		Name:        "remote",
		Summary:     "Check the access to the storage",
		Description: "Commands to fetch the host keys of an SFTP server and to check the login and the repository directory without changing anything.",
		Commands:    []*cli.Command{remoteCheckCommand(), remoteHostkeyCommand()},
	}
}

func remoteCheckCommand() *cli.Command {
	return &cli.Command{
		Name:    "check",
		Summary: "Connect to the storage and check access, changing nothing",
		Description: `Connects to the storage given by --remote and reports the host key and where it was confirmed, the login method that worked, the SFTP version and extensions, the real path of the repository directory and the suites found in it.

Nothing is changed. With --write-test a probe file is created next to where a publish would write and removed again.`,
		Flags: func(fs *flag.FlagSet) {
			remoteFlag(fs, false)
			accessFlags(fs, 2*time.Minute)
			fs.Bool("write-test", false, "create and remove a probe file to check write access")
			outputFlags(fs, true)
		},
		Env:     accessEnv,
		Secrets: accessSecrets,
		Run:     runRemoteCheck,
	}
}

func remoteHostkeyCommand() *cli.Command {
	return &cli.Command{
		Name:    "hostkey",
		Args:    "HOST[:PORT]",
		Summary: "Fetch the host keys of an SFTP server for known_hosts",
		Description: `Connects to HOST on PORT (default 22) once per host key algorithm, like ssh-keyscan, and writes a known_hosts line for every key on standard output. The fingerprints go to standard error.

Anybody between you and the server could answer instead of it. Compare the fingerprints over a second channel, such as the documentation of the provider, before trusting the lines.`,
		Flags: func(fs *flag.FlagSet) {
			fs.String("type", "", "fetch only keys of this `TYPE`: ed25519, ecdsa or rsa")
			fs.Duration("timeout", 30*time.Second, "give up after this `DURATION` per connection")
			outputFlags(fs, false)
		},
		Run: runRemoteHostkey,
	}
}

// hostKeyGroups are the connections of remote hostkey: one per key type,
// with the algorithms that identify it.
var hostKeyGroups = []struct {
	name  string
	algos []string
}{
	{"ed25519", []string{ssh.KeyEd25519}},
	{"ecdsa", []string{ssh.KeyECDSA256, ssh.KeyECDSA384, ssh.KeyECDSA521}},
	{"rsa", []string{ssh.SigRSASHA512, ssh.SigRSASHA256}},
}

// runRemoteHostkey fetches the host keys of a server.
func runRemoteHostkey(ctx context.Context, inv *cli.Invocation) error {
	if len(inv.Args) != 1 {
		return inv.Usagef("name exactly one HOST[:PORT]")
	}
	addr, err := hostPort(inv.Args[0])
	if err != nil {
		return inv.Usagef("%v", err)
	}
	typ := inv.String("type")
	if typ != "" && !slicesContainsGroup(typ) {
		return inv.Usagef("--type must be ed25519, ecdsa or rsa")
	}
	found := 0
	for _, g := range hostKeyGroups {
		if typ != "" && typ != g.name {
			continue
		}
		key, algos, err := ssh.FetchHostKey(ctx, addr, g.algos, timeout(inv))
		if err != nil {
			if strings.Contains(err.Error(), "no common host key algorithm") {
				inv.Verbose("%s has no %s host key", addr, g.name)
				continue
			}
			return err
		}
		inv.Verbose("Negotiated %s", algos)
		fmt.Fprintln(inv.Stdout, knownhosts.FormatLine(addr, key))
		inv.Say("%s %s", key.Type(), ssh.Fingerprint(key))
		found++
	}
	if found == 0 {
		return fmt.Errorf("%s offered no host key of the requested type", addr)
	}
	inv.Warn("anybody between you and %s could have answered; compare these fingerprints over a second channel, such as the documentation of the provider, before adding the lines to known_hosts", addr)
	return nil
}

func slicesContainsGroup(name string) bool {
	for _, g := range hostKeyGroups {
		if g.name == name {
			return true
		}
	}
	return false
}

// hostPort reads HOST[:PORT] with port 22 as default; IPv6 in brackets.
func hostPort(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty host")
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid HOST[:PORT] %q", s)
		}
		return net.JoinHostPort(host, port), nil
	}
	return net.JoinHostPort(strings.Trim(s, "[]"), "22"), nil
}

// runRemoteCheck checks access to the storage.
func runRemoteCheck(ctx context.Context, inv *cli.Invocation) error {
	if len(inv.Args) > 0 {
		return inv.Usagef("unexpected argument %q", inv.Args[0])
	}
	if inv.String("remote") == "" {
		return inv.Usagef("--remote or WDYAPT_REMOTE is required")
	}
	if t := timeout(inv); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	st, err := openStore(ctx, inv)
	if err != nil {
		return err
	}
	defer st.Close()
	rep, err := store.Check(ctx, st, inv.Bool("write-test"))
	if err != nil {
		return err
	}
	if inv.Bool("json") {
		return inv.JSON(rep)
	}
	w := inv.Stdout
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-15s %s\n", k+":", v)
		}
	}
	line("storage", rep.Storage)
	line("host key", rep.HostKey)
	line("algorithms", rep.Algorithms)
	line("login", rep.Login)
	if rep.SFTPVersion > 0 {
		line("sftp", fmt.Sprintf("version %d, extensions %s", rep.SFTPVersion, strings.Join(rep.Extensions, ", ")))
		if !rep.AtomicReplace {
			line("warning", "no posix-rename@openssh.com: files are replaced by removing them first")
		}
	}
	root := rep.Root
	if !rep.RootExists {
		root += " (does not exist yet; publish --create creates it)"
	}
	line("root", root)
	suites := strings.Join(rep.Suites, ", ")
	if suites == "" {
		suites = "none"
	}
	line("suites", suites)
	line("lock", rep.Lock)
	line("write test", rep.WriteTest)
	return nil
}
