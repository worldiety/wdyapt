// Package cli gives wdyapt a command line that explains itself
// (R-NFR-SELF-EXPLAINING-CLI) and serves humans as well as pipelines
// (R-NFR-HUMANS-AND-PIPELINES). Program.Check verifies this for a program.
//
// A program is a tree of commands. A command with Run is executable; a
// command without Run is a group and explains its subcommands when invoked.
// Every program gets the commands help and version for free, and every
// command understands -h and --help.
//
// Arguments are read with flag.FlagSet from the standard library. Only what
// it lacks is added: an argument can take its value from an environment
// variable, options can be repeated (List), and secrets that exist only as
// environment variables are explained by the help in a section of their own
// (Secret).
//
// All text a user sees is English.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// Exit codes as shell scripts and pipelines expect them.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
	// ExitTemporary reports a temporary obstacle, such as a held lock; a
	// pipeline may retry the run (EX_TEMPFAIL).
	ExitTemporary = 75
)

// ErrUsage reports an invocation that does not fit the program. The
// explanation has already been printed.
var ErrUsage = errors.New("usage error")

// ErrTemporary marks an error after which another run may succeed. Main then
// exits with ExitTemporary.
var ErrTemporary = errors.New("temporary failure")

// Temporary wraps err so that errors.Is(err, ErrTemporary) holds.
func Temporary(err error) error {
	if err == nil {
		return nil
	}
	return temporaryError{err}
}

type temporaryError struct{ error }

func (e temporaryError) Unwrap() error { return e.error }

func (e temporaryError) Is(target error) bool { return target == ErrTemporary }

// Program describes an executable.
type Program struct {
	// Name is the file name of the program, such as "wdyapt".
	Name string
	// Summary is one sentence that states the purpose.
	Summary string
	// Description explains in a few paragraphs what the program is for and
	// how to get started. Paragraphs are separated by blank lines.
	Description string
	// Version is printed by "version".
	Version string
	// Commands are the top-level commands.
	Commands []*Command
}

// Command is a command or a group of commands.
type Command struct {
	// Name is the word that invokes the command.
	Name string
	// Args describes the positional arguments for the help, such as "FILE...".
	Args string
	// Summary is one sentence for the command list.
	Summary string
	// Description explains in detail what the command does.
	Description string
	// Flags registers the arguments of the command.
	Flags func(fs *flag.FlagSet)
	// Env maps an argument to an environment variable whose value applies when
	// the argument was not given.
	Env map[string]string
	// Secrets are environment variables without an option, such as a password
	// that must not appear in the process list.
	Secrets []Secret
	// Run executes the command. Without Run, the command is a group.
	Run func(ctx context.Context, inv *Invocation) error
	// Commands are the subcommands of a group.
	Commands []*Command
}

// Secret is an environment variable that exists only as such.
type Secret struct {
	// Variable is the name, such as "WDYAPT_SFTP_PASSWORD".
	Variable string
	// Help explains what the variable contains.
	Help string
}

// Invocation is a single invocation of a command.
type Invocation struct {
	// Program is the invoked program.
	Program *Program
	// Path holds the names from the program down to the command, such as
	// ["wdyapt", "deb", "build"].
	Path []string
	// Flags holds the parsed arguments.
	Flags *flag.FlagSet
	// Args are the positional arguments after the flags.
	Args []string
	// Stdout receives the result of a command, such as written paths.
	Stdout io.Writer
	// Stderr receives help, errors and progress messages so that scripts can
	// process Stdout further.
	Stderr io.Writer
	// Getenv reads environment variables.
	Getenv func(string) string

	// fromEnv names the options whose value came from the environment.
	fromEnv map[string]bool
}

// Bool returns the value of the boolean option name; false if there is no
// such option.
func (inv *Invocation) Bool(name string) bool {
	f := inv.Flags.Lookup(name)
	if f == nil {
		return false
	}
	g, ok := f.Value.(flag.Getter)
	if !ok {
		return false
	}
	b, _ := g.Get().(bool)
	return b
}

// String returns the value of the option name as text; empty if there is no
// such option.
func (inv *Invocation) String(name string) string {
	f := inv.Flags.Lookup(name)
	if f == nil {
		return ""
	}
	return f.Value.String()
}

// Given reports whether the option name was set on the command line or via
// its environment variable.
func (inv *Invocation) Given(name string) bool {
	given := inv.fromEnv[name]
	inv.Flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}

// Say reports in one line on Stderr what the program is doing. With --quiet
// it stays silent.
func (inv *Invocation) Say(format string, args ...any) {
	if inv.Bool("quiet") {
		return
	}
	fmt.Fprintf(inv.Stderr, format+"\n", args...)
}

// Verbose reports details, but only with --verbose.
func (inv *Invocation) Verbose(format string, args ...any) {
	if !inv.Bool("verbose") || inv.Bool("quiet") {
		return
	}
	fmt.Fprintf(inv.Stderr, format+"\n", args...)
}

// Warn reports a warning on Stderr, even with --quiet.
func (inv *Invocation) Warn(format string, args ...any) {
	fmt.Fprintf(inv.Stderr, "warning: "+format+"\n", args...)
}

// Usagef reports wrong usage with a pointer to the help and returns
// ErrUsage, which Main reports as exit code 2.
func (inv *Invocation) Usagef(format string, args ...any) error {
	path := strings.Join(inv.Path, " ")
	hint := append([]string{inv.Path[0], "help"}, inv.Path[1:]...)
	fmt.Fprintf(inv.Stderr, "%s: %s\nRun \"%s\" to learn more.\n", path, fmt.Sprintf(format, args...), strings.Join(hint, " "))
	return ErrUsage
}

// JSON writes v as an indented JSON document to Stdout.
func (inv *Invocation) JSON(v any) error {
	enc := json.NewEncoder(inv.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Environment is the environment a program runs in.
type Environment struct {
	// Args are the arguments without the program name.
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
}

// OS returns the environment of the running process.
func OS() Environment {
	return Environment{Args: os.Args[1:], Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv}
}

// Main runs the program and returns the exit code.
func (p *Program) Main(ctx context.Context, env Environment) int {
	err := p.Run(ctx, env)
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, ErrUsage):
		return ExitUsage
	case errors.Is(err, ErrTemporary):
		fmt.Fprintf(env.Stderr, "%s: error: %v\n", p.Name, err)
		return ExitTemporary
	default:
		fmt.Fprintf(env.Stderr, "%s: error: %v\n", p.Name, err)
		return ExitError
	}
}

// Run selects the command from env.Args and executes it.
func (p *Program) Run(ctx context.Context, env Environment) error {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	return p.dispatch(ctx, env, p.root(), []string{p.Name}, env.Args)
}

// root is the program as the group of its commands, extended by help and
// version unless the program brings its own.
func (p *Program) root() *Command {
	cmds := slices.Clone(p.Commands)
	if find(cmds, "help") == nil {
		cmds = append(cmds, &Command{
			Name:        "help",
			Args:        "[COMMAND...]",
			Summary:     "Explain the program or one of its commands",
			Description: "Without arguments, help explains what this program is for and lists its commands. Followed by COMMAND, the name of a command and of its subcommands, help explains that command, its options and the environment variables it reads.",
			Run: func(_ context.Context, inv *Invocation) error {
				return p.help(inv.Stdout, inv.Stderr, inv.Args)
			},
		})
	}
	if find(cmds, "version") == nil {
		cmds = append(cmds, &Command{
			Name:        "version",
			Summary:     "Print the version of this program",
			Description: "Prints the version this binary was built from.",
			Run: func(_ context.Context, inv *Invocation) error {
				fmt.Fprintf(inv.Stdout, "%s %s\n", p.Name, p.Version)
				return nil
			},
		})
	}
	return &Command{Name: p.Name, Summary: p.Summary, Description: p.Description, Commands: cmds}
}

func (p *Program) dispatch(ctx context.Context, env Environment, cmd *Command, path, args []string) error {
	if cmd.Run == nil {
		switch {
		case len(args) == 0 && len(path) == 1:
			// Starting the program without a command is the usual way to
			// ask what it is. That is not an error.
			writeHelp(env.Stdout, cmd, path)
			return nil
		case len(args) == 0:
			writeHelp(env.Stderr, cmd, path)
			return ErrUsage
		case isHelpFlag(args[0]):
			writeHelp(env.Stdout, cmd, path)
			return nil
		}
		sub := find(cmd.Commands, args[0])
		if sub == nil {
			fmt.Fprintf(env.Stderr, "%s: unknown command %q\n\n", strings.Join(path, " "), args[0])
			writeHelp(env.Stderr, cmd, path)
			return ErrUsage
		}
		return p.dispatch(ctx, env, sub, append(slices.Clip(path), sub.Name), args[1:])
	}

	fs := newFlagSet(cmd)
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeHelp(env.Stdout, cmd, path)
			return nil
		}
		fmt.Fprintf(env.Stderr, "%s: %v\n\n", strings.Join(path, " "), err)
		writeHelp(env.Stderr, cmd, path)
		return ErrUsage
	}
	fromEnv, err := applyEnv(fs, cmd.Env, env.Getenv)
	if err != nil {
		fmt.Fprintf(env.Stderr, "%s: %v\n", strings.Join(path, " "), err)
		return ErrUsage
	}
	return cmd.Run(ctx, &Invocation{
		Program: p,
		Path:    path,
		Flags:   fs,
		Args:    positional,
		Stdout:  env.Stdout,
		Stderr:  env.Stderr,
		Getenv:  env.Getenv,
		fromEnv: fromEnv,
	})
}

// parseInterspersed reads options after arguments too, so that
// "deb info a.deb --json" works as expected. After "--" everything is an
// argument.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		consumed := len(args) - len(rest)
		if len(rest) == 0 || consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// help explains the program or the command that names denotes.
func (p *Program) help(stdout, stderr io.Writer, names []string) error {
	cmd, path := p.root(), []string{p.Name}
	for _, n := range names {
		sub := find(cmd.Commands, n)
		if sub == nil {
			fmt.Fprintf(stderr, "%s: unknown command %q\n\n", strings.Join(path, " "), n)
			writeHelp(stderr, cmd, path)
			return ErrUsage
		}
		cmd, path = sub, append(path, n)
	}
	writeHelp(stdout, cmd, path)
	return nil
}

func newFlagSet(cmd *Command) *flag.FlagSet {
	fs := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	if cmd.Flags != nil {
		cmd.Flags(fs)
	}
	return fs
}

// envSetter sets a value from an environment variable differently than from
// the command line, such as a list separated by ":".
type envSetter interface {
	SetEnv(string) error
}

// applyEnv sets arguments that were not given from their environment
// variable and returns the names of those it set.
func applyEnv(fs *flag.FlagSet, env map[string]string, getenv func(string) string) (map[string]bool, error) {
	set := map[string]bool{}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for _, name := range sortedKeys(env) {
		if given[name] {
			continue
		}
		variable := env[name]
		v := getenv(variable)
		if v == "" {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		var err error
		if s, ok := f.Value.(envSetter); ok {
			err = s.SetEnv(v)
		} else {
			err = f.Value.Set(v)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid value in %s: %v", variable, err)
		}
		set[name] = true
	}
	return set, nil
}

func find(cmds []*Command, name string) *Command {
	for _, c := range cmds {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "-help" || arg == "--help"
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
