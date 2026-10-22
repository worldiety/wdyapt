package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// placeholder finds the placeholders in Command.Args, such as FILE or
// COMMAND in "[COMMAND...]".
var placeholder = regexp.MustCompile(`[A-Z][A-Z0-9_]*`)

// Check verifies that the program explains itself
// (R-NFR-SELF-EXPLAINING-CLI): the program and its commands have a summary
// and a description, every argument has a help, every placeholder of the
// positional arguments appears in the description, every environment
// variable belongs to an argument, every secret has an explanation, and no
// own command hides help or version. Check returns all shortcomings, nil if
// there are none.
func (p *Program) Check() error {
	var errs []error
	fail := func(path []string, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", strings.Join(path, " "), fmt.Sprintf(format, args...)))
	}
	for _, c := range p.Commands {
		if c.Name == "help" || c.Name == "version" {
			fail([]string{p.Name, c.Name}, "hides the built-in command %s", c.Name)
		}
	}
	var walk func(c *Command, path []string)
	walk = func(c *Command, path []string) {
		if strings.TrimSpace(c.Summary) == "" {
			fail(path, "no summary")
		}
		if strings.TrimSpace(c.Description) == "" {
			fail(path, "no description")
		}
		for _, name := range placeholder.FindAllString(c.Args, -1) {
			if !strings.Contains(c.Summary+" "+c.Description, name) {
				fail(path, "the description does not explain %s", name)
			}
		}
		fs := flag.NewFlagSet(c.Name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if c.Flags != nil {
			c.Flags(fs)
		}
		fs.VisitAll(func(f *flag.Flag) {
			if strings.TrimSpace(f.Usage) == "" {
				fail(path, "option --%s has no help", f.Name)
			}
		})
		for _, name := range sortedKeys(c.Env) {
			if fs.Lookup(name) == nil {
				fail(path, "environment variable %s belongs to no option --%s", c.Env[name], name)
			}
		}
		for _, s := range c.Secrets {
			if strings.TrimSpace(s.Variable) == "" {
				fail(path, "a secret has no variable")
			}
			if strings.TrimSpace(s.Help) == "" {
				fail(path, "secret %s has no explanation", s.Variable)
			}
		}
		if c.Run == nil && len(c.Commands) == 0 {
			fail(path, "neither runs nor has commands")
		}
		for _, sub := range c.Commands {
			walk(sub, append(append([]string(nil), path...), sub.Name))
		}
	}
	walk(p.root(), []string{p.Name})
	return errors.Join(errs...)
}
