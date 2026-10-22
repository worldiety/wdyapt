package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

type run struct {
	stdout, stderr string
	err            error
	inv            *Invocation
}

func sample(record **Invocation) *Program {
	capture := func(_ context.Context, inv *Invocation) error {
		*record = inv
		return nil
	}
	return &Program{
		Name:        "demo",
		Summary:     "A program for tests",
		Description: "Demo explains itself.\n\nIt has a second paragraph.",
		Version:     "1.2.3",
		Commands: []*Command{
			{
				Name:    "run",
				Summary: "Start the demo",
				Flags: func(fs *flag.FlagSet) {
					fs.String("data", "./demo.d", "data `DIR`ectory")
					fs.Bool("verbose", false, "say more")
					fs.Bool("quiet", false, "say nothing")
					fs.Var(&List{Sep: ":"}, "key", "a key `FILE`; repeatable")
					fs.Var(&List{Split: true}, "arch", "architectures `LIST`")
				},
				Env:     map[string]string{"data": "DEMO_DATA", "key": "DEMO_KEYS", "arch": "DEMO_ARCH"},
				Secrets: []Secret{{Variable: "DEMO_PASSWORD", Help: "the password of the demo"}},
				Run:     capture,
			},
			{
				Name:    "runner",
				Summary: "Manage runners",
				Commands: []*Command{
					{Name: "new", Args: "NAME", Summary: "Create a runner", Run: capture},
					{Name: "fail", Summary: "Always fails", Run: func(context.Context, *Invocation) error { return errors.New("boom") }},
					{Name: "busy", Summary: "Always busy", Run: func(context.Context, *Invocation) error {
						return Temporary(fmt.Errorf("lock held"))
					}},
					{Name: "misuse", Summary: "Always misused", Run: func(_ context.Context, inv *Invocation) error {
						return inv.Usagef("--suite is required")
					}},
				},
			},
		},
	}
}

func exec(t *testing.T, env map[string]string, args ...string) run {
	t.Helper()
	var inv *Invocation
	var out, errOut bytes.Buffer
	err := sample(&inv).Run(context.Background(), Environment{
		Args:   args,
		Stdout: &out,
		Stderr: &errOut,
		Getenv: func(k string) string { return env[k] },
	})
	return run{stdout: out.String(), stderr: errOut.String(), err: err, inv: inv}
}

func TestNoArgumentsExplainsProgram(t *testing.T) {
	r := exec(t, nil)
	if r.err != nil {
		t.Fatalf("err = %v", r.err)
	}
	for _, want := range []string{"demo - A program for tests", "Demo explains itself.", "second paragraph", "run ", "runner ", "help ", "version ", `Run "demo help COMMAND"`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}

func TestDispatchToNestedCommand(t *testing.T) {
	r := exec(t, nil, "runner", "new", "alpha")
	if r.err != nil {
		t.Fatalf("err = %v", r.err)
	}
	if got := strings.Join(r.inv.Path, " "); got != "demo runner new" {
		t.Errorf("path = %q", got)
	}
	if len(r.inv.Args) != 1 || r.inv.Args[0] != "alpha" {
		t.Errorf("args = %v", r.inv.Args)
	}
}

func TestFlagsMayFollowArguments(t *testing.T) {
	r := exec(t, nil, "run", "alpha", "--data", "x", "beta", "--verbose", "--", "--gamma")
	if r.err != nil {
		t.Fatalf("err = %v", r.err)
	}
	if got := strings.Join(r.inv.Args, " "); got != "alpha beta --gamma" {
		t.Errorf("args = %q", got)
	}
	if r.inv.String("data") != "x" || !r.inv.Bool("verbose") {
		t.Errorf("flags not parsed after arguments")
	}
}

func TestGroupWithoutCommandIsUsageError(t *testing.T) {
	r := exec(t, nil, "runner")
	if !errors.Is(r.err, ErrUsage) {
		t.Fatalf("err = %v, want ErrUsage", r.err)
	}
	if r.stdout != "" || !strings.Contains(r.stderr, "new ") || !strings.Contains(r.stderr, `"demo help runner COMMAND"`) {
		t.Errorf("stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	r := exec(t, nil, "nope")
	if !errors.Is(r.err, ErrUsage) {
		t.Fatalf("err = %v", r.err)
	}
	if !strings.Contains(r.stderr, `unknown command "nope"`) {
		t.Errorf("stderr:\n%s", r.stderr)
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}

func TestHelpFlagAndHelpCommandAgree(t *testing.T) {
	a := exec(t, nil, "run", "--help")
	b := exec(t, nil, "help", "run")
	if a.err != nil || b.err != nil {
		t.Fatalf("errs = %v, %v", a.err, b.err)
	}
	if a.stdout != b.stdout {
		t.Errorf("--help and help differ:\n%s\n---\n%s", a.stdout, b.stdout)
	}
	for _, want := range []string{
		"Usage:\n  demo run [options]", "--data DIR", "default: ./demo.d", "environment: DEMO_DATA",
		"--verbose\n", "--key FILE", "environment: DEMO_KEYS",
		"Environment:\n  DEMO_PASSWORD\n      the password of the demo",
	} {
		if !strings.Contains(a.stdout, want) {
			t.Errorf("help lacks %q:\n%s", want, a.stdout)
		}
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}

func TestEnvironmentFillsUnsetFlag(t *testing.T) {
	r := exec(t, map[string]string{"DEMO_DATA": "/srv/demo", "DEMO_KEYS": "a.asc:b.asc", "DEMO_ARCH": "amd64, arm64"}, "run")
	if got := r.inv.String("data"); got != "/srv/demo" {
		t.Errorf("data = %q", got)
	}
	if got := r.inv.Flags.Lookup("key").Value.(*List).Values; strings.Join(got, "|") != "a.asc|b.asc" {
		t.Errorf("key = %q", got)
	}
	if got := r.inv.Flags.Lookup("arch").Value.(*List).Values; strings.Join(got, "|") != "amd64|arm64" {
		t.Errorf("arch = %q", got)
	}
	if !r.inv.Given("data") || !r.inv.Given("key") || r.inv.Given("verbose") {
		t.Errorf("Given does not report options from the environment")
	}
}

func TestFlagWinsOverEnvironment(t *testing.T) {
	r := exec(t, map[string]string{"DEMO_DATA": "/srv/demo", "DEMO_KEYS": "a.asc"}, "run", "--data", "here", "--key", "c.asc", "--key", "d:e.asc", "--arch", "i386,all")
	if got := r.inv.String("data"); got != "here" {
		t.Errorf("data = %q", got)
	}
	if got := r.inv.Flags.Lookup("key").Value.(*List).Values; strings.Join(got, "|") != "c.asc|d:e.asc" {
		t.Errorf("key = %q", got)
	}
	if got := r.inv.Flags.Lookup("arch").Value.(*List).Values; strings.Join(got, "|") != "i386|all" {
		t.Errorf("arch = %q", got)
	}
}

func TestBadFlagIsUsageError(t *testing.T) {
	r := exec(t, nil, "run", "--nope")
	if !errors.Is(r.err, ErrUsage) {
		t.Fatalf("err = %v", r.err)
	}
	if !strings.Contains(r.stderr, "flag provided but not defined: -nope") {
		t.Errorf("stderr:\n%s", r.stderr)
	}
}

func TestVersion(t *testing.T) {
	r := exec(t, nil, "version")
	if r.stdout != "demo 1.2.3\n" {
		t.Errorf("stdout = %q", r.stdout)
	}
}

func TestSayHonoursQuietAndVerbose(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "step\nwarning: careful\n"},
		{[]string{"--verbose"}, "step\ndetail\nwarning: careful\n"},
		{[]string{"--quiet", "--verbose"}, "warning: careful\n"},
	} {
		r := exec(t, nil, append([]string{"run"}, tc.args...)...)
		var b bytes.Buffer
		r.inv.Stderr = &b
		r.inv.Say("step")
		r.inv.Verbose("detail")
		r.inv.Warn("careful")
		if b.String() != tc.want {
			t.Errorf("%v: %q, want %q", tc.args, b.String(), tc.want)
		}
	}
}

func TestMainExitCodes(t *testing.T) {
	var inv *Invocation
	p := sample(&inv)
	for _, tc := range []struct {
		args   []string
		want   int
		stderr string
	}{
		{nil, ExitOK, ""},
		{[]string{"nope"}, ExitUsage, `unknown command "nope"`},
		{[]string{"runner", "fail"}, ExitError, "demo: error: boom"},
		{[]string{"runner", "busy"}, ExitTemporary, "demo: error: lock held"},
		{[]string{"runner", "misuse"}, ExitUsage, "demo runner misuse: --suite is required\nRun \"demo help runner misuse\""},
	} {
		var errOut bytes.Buffer
		got := p.Main(context.Background(), Environment{Args: tc.args, Stdout: &bytes.Buffer{}, Stderr: &errOut})
		if got != tc.want {
			t.Errorf("%v: exit %d, want %d", tc.args, got, tc.want)
		}
		if !strings.Contains(errOut.String(), tc.stderr) {
			t.Errorf("%v: stderr = %q", tc.args, errOut.String())
		}
	}
}

func TestJSONWritesOneDocument(t *testing.T) {
	var out bytes.Buffer
	inv := &Invocation{Stdout: &out}
	if err := inv.JSON(map[string]any{"path": "a<b>.deb"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "{\n  \"path\": \"a<b>.deb\"\n}\n" {
		t.Errorf("json = %q", out.String())
	}
}

func TestWriteTextWrapsAndKeepsIndentedBlocks(t *testing.T) {
	var b bytes.Buffer
	long := strings.Repeat("word ", 40)
	writeText(&b, long+"\n\n  demo run --data x\n  demo version", "  ")
	for line := range strings.SplitSeq(strings.TrimRight(b.String(), "\n"), "\n") {
		if len(line) > lineWidth {
			t.Errorf("line too long (%d): %q", len(line), line)
		}
	}
	if !strings.Contains(b.String(), "\n    demo run --data x\n    demo version\n") {
		t.Errorf("indented block changed:\n%s", b.String())
	}
	spec.Verified(t, nfr.RNfrSelfExplainingCli)
}
