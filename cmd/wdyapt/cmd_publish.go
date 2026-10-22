package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/deb"
	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/publish"
	"github.com/worldiety/wdyapt/internal/repo"
	"github.com/worldiety/wdyapt/internal/store"
	"github.com/worldiety/wdyapt/internal/version"
)

func publishCommand() *cli.Command {
	return &cli.Command{
		Name:    "publish",
		Args:    "DEB|DIR...",
		Summary: "Add packages to a suite of a repository, sign and upload it",
		Description: `Adds Debian packages to a suite and component of an APT repository, signs the new Release and uploads everything. Every DEB is a package file; every DIR stands for the *.deb files in it (not recursive).

Before changing anything, publish reads the published state of the suite over the same connection it writes with, checks its signature against the signing keys and --trusted-key, and checks every package list against the Release. It never continues from a state it could not check, and it never replaces a published package with different content: a package that is already there with the same bytes is reported as unchanged.

The upload is ordered so that apt never sees half a state: new pool files first, then package lists and Release files under temporary names, then they are renamed into place with InRelease last. A lock file on the server keeps two runs apart; if the lock is held or the suite changed during the run, publish stops with exit code 75 so a pipeline may retry.

A suite that does not exist yet is only created with --create. Its Release then gets the fields --origin, --label, --codename and --description. In an existing suite these fields are kept as they are; giving different values is an error.

publish never deletes published packages and never removes entries from package lists.`,
		Flags: func(fs *flag.FlagSet) {
			remoteFlag(fs, false)
			fs.String("suite", "", "`NAME` of the suite, e.g. stable")
			fs.String("component", "main", "`NAME` of the component")
			fs.Bool("create", false, "allow creating the suite, and the repository directory, if they do not exist")
			fs.Var(&cli.List{Split: true}, "architectures", "`LIST` of architectures for a new suite, separated by commas; added to the architectures of an existing suite")
			fs.String("origin", "", "`TEXT` of the Origin field of a new suite")
			fs.String("label", "", "`TEXT` of the Label field of a new suite")
			fs.String("codename", "", "`TEXT` of the Codename field of a new suite; without it the suite name")
			fs.String("description", "", "`TEXT` of the Description field of a new suite")
			signingFlags(fs)
			trustedFlag(fs, "public OpenPGP key `FILE` the published state may also be signed with, e.g. the previous key during a key change; repeatable")
			accessFlags(fs, 30*time.Minute)
			fs.Int64("date", 0, "Date of the new Release in Unix `SECONDS` (default now); always later than the previous Date")
			fs.Bool("dry-run", false, "show what would be uploaded and signed, write nothing to the repository")
			fs.String("out", "", "also write the new package lists and Release files into `DIR`")
			fs.Duration("wait-for-lock", 0, "wait up to this `DURATION` for a lock held by another run")
			fs.Bool("break-lock", false, "remove a lock left by another run before starting")
			outputFlags(fs, true)
		},
		Env:     envOf(accessEnv, signingEnv, trustedEnv, map[string]string{"suite": "WDYAPT_SUITE", "component": "WDYAPT_COMPONENT"}),
		Secrets: secretsOf(accessSecrets, signingSecrets),
		Run:     runPublish,
	}
}

// runPublish publishes packages.
func runPublish(ctx context.Context, inv *cli.Invocation) error {
	if len(inv.Args) == 0 {
		return inv.Usagef("name at least one DEB file or DIR")
	}
	suite := inv.String("suite")
	if suite == "" {
		return inv.Usagef("--suite or WDYAPT_SUITE is required")
	}
	if inv.String("remote") == "" {
		return inv.Usagef("--remote or WDYAPT_REMOTE is required")
	}
	if r, err := store.ParseRemote(inv.String("remote")); err != nil {
		return inv.Usagef("%v", err)
	} else if r.Kind == store.KindHTTP {
		return inv.Usagef("%s is read-only; publish needs sftp:// or a directory", r.URL)
	}
	files, err := debFiles(inv.Args)
	if err != nil {
		return err
	}
	var pkgs []*repo.Package
	for _, name := range files {
		info, err := deb.ReadFile(name, false)
		if err != nil {
			return err
		}
		pkgs = append(pkgs, &repo.Package{Info: info, Name: name, Open: func() (io.ReadCloser, error) { return os.Open(name) }})
	}
	date := time.Now()
	if inv.Given("date") {
		date = time.Unix(inv.Flags.Lookup("date").Value.(flag.Getter).Get().(int64), 0)
	}
	passphrase, err := secretFrom(inv, "WDYAPT_SIGNING_KEY_PASSPHRASE", "passphrase-file")
	if err != nil {
		return err
	}
	signers, err := loadSigningKeys(inv, keyFiles(inv, "signing-key"), passphrase, time.Now())
	if err != nil {
		return err
	}
	trusted, err := loadTrustedKeys(keyFiles(inv, "trusted-key"))
	if err != nil {
		return err
	}
	ring := openpgp.NewKeyring(signers...)
	ring.Add(trusted...)

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

	host, _ := os.Hostname()
	userName := ""
	if u, err := user.Current(); err == nil {
		userName = u.Username
	}
	res, err := publish.Run(ctx, st, publish.Input{
		Suite: suite, Component: inv.String("component"), Packages: pkgs,
		Signers: signers, Keyring: ring,
		Create: inv.Bool("create"), Architectures: inv.Flags.Lookup("architectures").Value.(*cli.List).Values,
		Origin: inv.String("origin"), Label: inv.String("label"), Codename: inv.String("codename"), Description: inv.String("description"),
		Date: date, DryRun: inv.Bool("dry-run"), OutDir: inv.String("out"),
		WaitForLock: inv.Flags.Lookup("wait-for-lock").Value.(flag.Getter).Get().(time.Duration),
		BreakLock:   inv.Bool("break-lock"),
		Lock:        publish.LockInfo{Host: host, User: userName, PID: os.Getpid(), Started: time.Now().UTC(), Version: version.String(), Suite: suite},
		Say:         inv.Say,
		Warn:        inv.Warn,
	})
	if errors.Is(err, publish.ErrBusy) {
		return cli.Temporary(err)
	}
	if err != nil {
		return err
	}
	if inv.Bool("json") {
		return inv.JSON(res)
	}
	for _, a := range res.Added {
		verb := "added"
		if res.DryRun {
			verb = "would add"
		}
		fmt.Fprintf(inv.Stdout, "%s %s %s %s %s\n", verb, a.Package, a.Version, a.Architecture, a.Filename)
	}
	for _, u := range res.Unchanged {
		fmt.Fprintf(inv.Stdout, "unchanged %s %s %s %s\n", u.Package, u.Version, u.Architecture, u.Filename)
	}
	if res.DryRun && res.Changed {
		fmt.Fprintf(inv.Stdout, "\nThe new dists/%s/Release would be:\n\n%s", suite, res.Release)
	}
	return nil
}

// debFiles resolves the arguments: files stay, a directory stands for the
// *.deb in it, not recursively.
func debFiles(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, a)
			continue
		}
		entries, err := os.ReadDir(a)
		if err != nil {
			return nil, err
		}
		var found []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".deb") {
				found = append(found, filepath.Join(a, e.Name()))
			}
		}
		if len(found) == 0 {
			return nil, fmt.Errorf("%s contains no *.deb files", a)
		}
		slices.Sort(found)
		out = append(out, found...)
	}
	return out, nil
}
