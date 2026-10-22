// Command wdyapt builds Debian packages from finished programs and publishes
// them signed to an APT repository on SFTP storage.
//
// main.go only wires things up: it builds the program from the commands of
// the files cmd_*.go and runs it with a context that SIGINT and SIGTERM
// cancel.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := program().Main(ctx, cli.OS())
	stop()
	os.Exit(code)
}

// program describes wdyapt with all its commands.
func program() *cli.Program {
	return &cli.Program{
		Name:    "wdyapt",
		Summary: "Build Debian packages and publish them to an APT repository",
		Description: `wdyapt turns finished programs and other files into Debian packages and publishes them, signed, into a suite of an APT repository on an SFTP server or in a directory. It needs no other program: it speaks SSH, SFTP and OpenPGP itself.

A typical start:

  wdyapt key generate --user-id "Example APT <apt@example.com>" --out apt
  wdyapt remote hostkey sftp.example.com >> known_hosts
  wdyapt deb build --name hello --version 1.0-1 --arch amd64 \
    --maintainer "Example <dev@example.com>" --summary "Says hello" \
    --file 'hello_{arch}:/usr/bin/hello:0755' --out build/
  WDYAPT_SFTP_PASSWORD=... wdyapt publish --create --suite stable \
    --remote sftp://user@sftp.example.com/~/repo --known-hosts known_hosts \
    --signing-key apt.secret.asc build/

wdyapt never asks questions. Options can also be set through environment variables named in the help of each command; secrets such as passwords are read only from the environment or from files. Results go to standard output, progress and errors to standard error. Exit codes: 0 success, 1 error, 2 wrong usage, 75 temporary failure (a pipeline may retry).`,
		Version: version.String(),
		Commands: []*cli.Command{
			debCommand(),
			publishCommand(),
			repoCommand(),
			keyCommand(),
			remoteCommand(),
		},
	}
}

// outputFlags registers --json, --quiet and --verbose.
func outputFlags(fs *flag.FlagSet, withJSON bool) {
	if withJSON {
		fs.Bool("json", false, "write the result as one JSON document to standard output")
	}
	fs.Bool("quiet", false, "do not report progress on standard error")
	fs.Bool("verbose", false, "report protocol details such as negotiated algorithms")
}
