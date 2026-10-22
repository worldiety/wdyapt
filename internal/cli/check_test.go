package cli

import (
	"context"
	"flag"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

// A program that explains itself passes the check.
func TestCheckAcceptsASelfExplainingProgram(t *testing.T) {
	p := &Program{
		Name:        "demo",
		Summary:     "A program for tests",
		Description: "Demo explains itself.",
		Commands: []*Command{{
			Name:        "show",
			Args:        "FILE...",
			Summary:     "Show files",
			Description: "Shows every FILE.",
			Flags:       func(fs *flag.FlagSet) { fs.String("out", "out", "the output `DIRECTORY`") },
			Env:         map[string]string{"out": "DEMO_OUT"},
			Secrets:     []Secret{{Variable: "DEMO_PASSWORD", Help: "the password"}},
			Run:         func(context.Context, *Invocation) error { return nil },
		}},
	}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}

// The check finds every command, every argument and every secret without an
// explanation.
func TestCheckFindsWhatIsNotExplained(t *testing.T) {
	noop := func(context.Context, *Invocation) error { return nil }
	p := &Program{
		Name:        "demo",
		Summary:     "A program for tests",
		Description: "Demo explains itself.",
		Commands: []*Command{
			{Name: "version", Summary: "Shows versions of something else", Description: "Hides the built-in.", Run: noop},
			{Name: "silent", Run: noop},
			{Name: "join", Args: "TOKEN", Summary: "Join", Description: "Joins with a token.", Run: noop},
			{Name: "start", Summary: "Start", Description: "Starts.", Run: noop,
				Flags:   func(fs *flag.FlagSet) { fs.String("port", "", "") },
				Env:     map[string]string{"listen": "DEMO_LISTEN"},
				Secrets: []Secret{{Variable: "DEMO_SECRET"}},
			},
			{Name: "empty", Summary: "Nothing", Description: "Has neither Run nor commands."},
		},
	}
	err := p.Check()
	if err == nil {
		t.Fatal("no findings")
	}
	for _, want := range []string{
		"demo version: hides the built-in command version",
		"demo silent: no summary",
		"demo silent: no description",
		"demo join: the description does not explain TOKEN",
		"demo start: option --port has no help",
		"demo start: environment variable DEMO_LISTEN belongs to no option --listen",
		"demo start: secret DEMO_SECRET has no explanation",
		"demo empty: neither runs nor has commands",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing finding %q in:\n%v", want, err)
		}
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}
