package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

// wdyapt explains itself: every command and every argument has a help
// (R-NFR-SELF-EXPLAINING-CLI).
func TestProgramExplainsItself(t *testing.T) {
	if err := program().Check(); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := program().Main(context.Background(), cli.Environment{Stdout: &out, Stderr: &errOut})
	if code != cli.ExitOK || errOut.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	for _, want := range []string{"wdyapt - ", "deb ", "publish ", "repo ", "key ", "remote ", "help ", "version "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("program help lacks %q", want)
		}
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}

// Every help appears on Stdout and fits a terminal with 80 columns.
func TestHelpFitsTheTerminal(t *testing.T) {
	p := program()
	n := 0
	p.Walk(func(names []string, _ *cli.Command) {
		var b bytes.Buffer
		if err := p.Help(&b, names...); err != nil {
			t.Fatalf("%v: %v", names, err)
		}
		for i, line := range strings.Split(b.String(), "\n") {
			if len([]rune(line)) > 80 {
				t.Errorf("wdyapt help %s: line %d has %d columns: %q", strings.Join(names, " "), i+1, len([]rune(line)), line)
			}
		}
		n++
	})
	if n < 15 {
		t.Fatalf("only %d commands walked", n)
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}

// Groups without a command explain themselves on Stderr and exit with 2.
func TestGroupsExplainTheirCommands(t *testing.T) {
	for _, group := range []string{"deb", "repo", "key", "remote"} {
		var out, errOut bytes.Buffer
		code := program().Main(context.Background(), cli.Environment{Args: []string{group}, Stdout: &out, Stderr: &errOut})
		if code != cli.ExitUsage || out.Len() != 0 || !strings.Contains(errOut.String(), "Commands:") {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", group, code, out.String(), errOut.String())
		}
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}
