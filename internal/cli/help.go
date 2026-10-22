package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// lineWidth is the width descriptions are wrapped to. It fits a terminal
// with 80 columns.
const lineWidth = 78

// writeHelp explains a command: what it is for, how to invoke it and which
// subcommands, arguments and environment variables it knows.
func writeHelp(w io.Writer, cmd *Command, path []string) {
	name := strings.Join(path, " ")
	if cmd.Summary != "" {
		writeText(w, fmt.Sprintf("%s - %s", name, cmd.Summary), "")
		fmt.Fprintln(w)
	}
	if cmd.Description != "" {
		writeText(w, cmd.Description, "")
		fmt.Fprintln(w)
	}

	fs := newFlagSet(cmd)
	hasFlags := false
	fs.VisitAll(func(*flag.Flag) { hasFlags = true })

	fmt.Fprintln(w, "Usage:")
	usage := name
	if cmd.Run == nil {
		usage += " COMMAND"
	}
	if hasFlags {
		usage += " [options]"
	}
	if cmd.Args != "" {
		usage += " " + cmd.Args
	}
	writeText(w, usage, "  ")

	if cmd.Run == nil && len(cmd.Commands) > 0 {
		fmt.Fprintln(w, "\nCommands:")
		tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		for _, c := range cmd.Commands {
			fmt.Fprintf(tw, "  %s\t%s\n", c.Name, c.Summary)
		}
		tw.Flush()
	}

	if hasFlags {
		fmt.Fprintln(w, "\nOptions:")
		fs.VisitAll(func(f *flag.Flag) {
			typ, usage := flag.UnquoteUsage(f)
			head := "  --" + f.Name
			if typ != "" {
				head += " " + typ
			}
			fmt.Fprintln(w, head)
			var notes []string
			if !isZeroDefault(f.DefValue) {
				notes = append(notes, fmt.Sprintf("default: %s", f.DefValue))
			}
			if v, ok := cmd.Env[f.Name]; ok {
				notes = append(notes, "environment: "+v)
			}
			if len(notes) > 0 {
				usage += " (" + strings.Join(notes, ", ") + ")"
			}
			writeText(w, usage, "      ")
		})
	}

	if len(cmd.Secrets) > 0 {
		fmt.Fprintln(w, "\nEnvironment:")
		for _, s := range cmd.Secrets {
			fmt.Fprintln(w, "  "+s.Variable)
			writeText(w, s.Help, "      ")
		}
	}

	if cmd.Run == nil {
		hint := append([]string{path[0], "help"}, path[1:]...)
		fmt.Fprintf(w, "\nRun \"%s COMMAND\" to learn more about a command.\n", strings.Join(hint, " "))
	}
}

func isZeroDefault(v string) bool {
	return v == "" || v == "false" || v == "0" || v == "0s"
}

// writeText writes text in paragraphs, wrapped at lineWidth and indented by
// indent. A blank line separates paragraphs. A paragraph whose first line is
// indented stays as it is; this is how examples can be shown.
func writeText(w io.Writer, text, indent string) {
	paragraphs := strings.Split(strings.Trim(text, "\n"), "\n\n")
	for i, p := range paragraphs {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if strings.HasPrefix(p, " ") || strings.HasPrefix(p, "\t") {
			for line := range strings.SplitSeq(p, "\n") {
				fmt.Fprintln(w, indent+line)
			}
			continue
		}
		line := indent
		for _, word := range strings.Fields(p) {
			if len(line) > len(indent) && len(line)+1+len(word) > lineWidth {
				fmt.Fprintln(w, line)
				line = indent
			}
			if len(line) > len(indent) {
				line += " "
			}
			line += word
		}
		if len(line) > len(indent) {
			fmt.Fprintln(w, line)
		}
	}
}

// Help writes the help of the command that names denotes to w; empty names
// for the program itself. Tests use it to check every help.
func (p *Program) Help(w io.Writer, names ...string) error {
	return p.help(w, w, names)
}

// Walk calls fn for every command of the program, including help and
// version, with the path without the program name.
func (p *Program) Walk(fn func(names []string, cmd *Command)) {
	var walk func(c *Command, names []string)
	walk = func(c *Command, names []string) {
		fn(names, c)
		for _, sub := range c.Commands {
			walk(sub, append(append([]string(nil), names...), sub.Name))
		}
	}
	walk(p.root(), nil)
}
