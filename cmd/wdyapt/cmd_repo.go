package main

import (
	"context"
	"flag"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/repo"
)

// repoCommand is the group "repo": read a published repository.
func repoCommand() *cli.Command {
	return &cli.Command{
		Name:        "repo",
		Summary:     "Read and check a published repository",
		Description: "Commands that read a published APT repository without changing it: list the packages of a suite and check signatures, checksums and files.",
		Commands:    []*cli.Command{repoListCommand(), repoVerifyCommand()},
	}
}

func repoListCommand() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Summary: "List the packages of a suite",
		Description: `Lists package, version, architecture, size and pool path of every package in a suite.

With --trusted-key the Release is checked against those keys and every package list against the Release before anything is listed. Without it the suite is read unchecked, which is said on standard error.`,
		Flags: func(fs *flag.FlagSet) {
			remoteFlag(fs, true)
			fs.String("suite", "", "`NAME` of the suite, e.g. stable")
			fs.String("component", "", "list only this component (`NAME`)")
			fs.String("arch", "", "list only this architecture (`ARCH`)")
			fs.String("package", "", "list only the package `NAME`")
			trustedFlag(fs, "public OpenPGP key `FILE` the suite must be signed with; repeatable")
			accessFlags(fs, 5*time.Minute)
			outputFlags(fs, true)
		},
		Env:     envOf(accessEnv, trustedEnv, map[string]string{"suite": "WDYAPT_SUITE", "component": "WDYAPT_COMPONENT"}),
		Secrets: accessSecrets,
		Run:     runRepoList,
	}
}

func repoVerifyCommand() *cli.Command {
	return &cli.Command{
		Name:    "verify",
		Summary: "Check signatures, checksums and files of a published repository",
		Description: `Checks a published repository: the signatures of InRelease and Release.gpg against --trusted-key, the size and SHA256 of every package list named in the Release, and that every pool file named in a list exists with the right size. With --check-pool the SHA256 of every pool file is checked too, which downloads all of them.

Without --suite every suite below dists/ is checked; that needs SFTP or a directory, over HTTPS --suite is required. All problems are reported, including temporary files and a lock left behind by an interrupted publish. The exit code is 1 if there is at least one problem.`,
		Flags: func(fs *flag.FlagSet) {
			remoteFlag(fs, true)
			fs.Var(&cli.List{Split: true}, "suite", "check only the suite `NAME`; repeatable, or separated by commas")
			trustedFlag(fs, "public OpenPGP key `FILE` the repository must be signed with; repeatable")
			fs.Bool("check-pool", false, "also check the SHA256 of every pool file (downloads all packages)")
			accessFlags(fs, 30*time.Minute)
			outputFlags(fs, true)
		},
		Env:     envOf(accessEnv, trustedEnv),
		Secrets: accessSecrets,
		Run:     runRepoVerify,
	}
}

// runRepoList lists the packages of a suite.
func runRepoList(ctx context.Context, inv *cli.Invocation) error {
	if len(inv.Args) > 0 {
		return inv.Usagef("unexpected argument %q", inv.Args[0])
	}
	suite := inv.String("suite")
	if suite == "" {
		return inv.Usagef("--suite or WDYAPT_SUITE is required")
	}
	if inv.String("remote") == "" {
		return inv.Usagef("--remote or WDYAPT_REMOTE is required")
	}
	trusted, err := loadTrustedKeys(keyFiles(inv, "trusted-key"))
	if err != nil {
		return err
	}
	var ring *openpgp.Keyring
	if len(trusted) > 0 {
		ring = openpgp.NewKeyring(trusted...)
	} else {
		inv.Warn("no --trusted-key: the suite is listed without checking its signature")
	}
	if t := timeout(inv); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	st, err := openReader(ctx, inv)
	if err != nil {
		return err
	}
	defer st.Close()
	state, err := repo.ReadSuite(ctx, st, suite, ring)
	if err != nil {
		return err
	}
	if !state.Exists {
		return fmt.Errorf("the suite %s does not exist in %s", suite, st.Describe())
	}
	entries := repo.List(state, repo.Filter{Component: inv.String("component"), Arch: inv.String("arch"), Package: inv.String("package")})
	if inv.Bool("json") {
		return inv.JSON(map[string]any{"suite": suite, "checked": state.Checked, "date": repo.FormatDate(state.Date), "packages": append([]repo.Entry{}, entries...)})
	}
	tw := tabwriter.NewWriter(inv.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tVERSION\tARCH\tSIZE\tFILENAME")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", e.Package, e.Version, e.Architecture, e.Size, e.Filename)
	}
	return tw.Flush()
}

// runRepoVerify checks a repository and exits with 1 on a defect.
func runRepoVerify(ctx context.Context, inv *cli.Invocation) error {
	if len(inv.Args) > 0 {
		return inv.Usagef("unexpected argument %q", inv.Args[0])
	}
	if inv.String("remote") == "" {
		return inv.Usagef("--remote or WDYAPT_REMOTE is required")
	}
	files := keyFiles(inv, "trusted-key")
	if len(files) == 0 {
		return inv.Usagef("--trusted-key or WDYAPT_TRUSTED_KEYS is required to check signatures")
	}
	trusted, err := loadTrustedKeys(files)
	if err != nil {
		return err
	}
	if t := timeout(inv); t > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	st, err := openReader(ctx, inv)
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := repo.Verify(ctx, st, openpgp.NewKeyring(trusted...), repo.VerifyOptions{
		Suites:    inv.Flags.Lookup("suite").Value.(*cli.List).Values,
		CheckPool: inv.Bool("check-pool"),
		Progress:  inv.Say,
	})
	if err != nil {
		return err
	}
	if inv.Bool("json") {
		if err := inv.JSON(res); err != nil {
			return err
		}
	} else {
		for _, p := range res.Problems {
			fmt.Fprintln(inv.Stdout, p.String())
		}
	}
	if len(res.Problems) > 0 {
		return fmt.Errorf("%d problem(s) found in %s", len(res.Problems), st.Describe())
	}
	inv.Say("%s is in order: %d suite(s), %d package entries", st.Describe(), len(res.Suites), res.Packages)
	return nil
}
