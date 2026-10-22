package cli

import "strings"

// List is a repeatable option: every occurrence on the command line adds a
// value. From the environment the whole list comes in one variable,
// separated by Sep (default ","). With Split, every occurrence on the
// command line is split at Sep too, as in "--arch amd64,arm64".
//
// Register with fs.Var(&list, "name", "help with `PLACEHOLDER`").
type List struct {
	Values []string
	Sep    string
	Split  bool
}

func (l *List) sep() string {
	if l.Sep == "" {
		return ","
	}
	return l.Sep
}

// String returns the values, separated by Sep.
func (l *List) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(l.Values, l.sep())
}

// Set adds a value from the command line.
func (l *List) Set(v string) error {
	if l.Split {
		return l.SetEnv(v)
	}
	l.Values = append(l.Values, v)
	return nil
}

// SetEnv adds the values of an environment variable, separated by Sep;
// empty parts are dropped.
func (l *List) SetEnv(v string) error {
	for part := range strings.SplitSeq(v, l.sep()) {
		if part = strings.TrimSpace(part); part != "" {
			l.Values = append(l.Values, part)
		}
	}
	return nil
}

// Get returns the values as []string.
func (l *List) Get() any { return l.Values }
