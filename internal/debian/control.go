// Package debian knows the Debian formats and rules that wdyapt needs:
// paragraphs of control files (deb822), package names, versions together
// with their dpkg ordering, and architectures.
package debian

import (
	"fmt"
	"strings"
)

// Field is a field of a paragraph. Value contains continuation lines with
// their indentation, separated by "\n"; a value that starts with "\n" has
// nothing on the first line (such as SHA256 in Release).
type Field struct {
	Key, Value string
}

// Paragraph is a paragraph of a control file: the control of a package, an
// entry in Packages or the Release file. The order of the fields is kept so
// that a paragraph that was read is written back unchanged.
type Paragraph []Field

// Get returns the value of the field key, ignoring case; empty if it is
// missing.
func (p Paragraph) Get(key string) string {
	v, _ := p.Lookup(key)
	return v
}

// Lookup returns the value of the field key and whether it is present.
func (p Paragraph) Lookup(key string) (string, bool) {
	for _, f := range p {
		if strings.EqualFold(f.Key, key) {
			return f.Value, true
		}
	}
	return "", false
}

// Set replaces the value of the field key in place or appends the field.
func (p Paragraph) Set(key, value string) Paragraph {
	for i, f := range p {
		if strings.EqualFold(f.Key, key) {
			p[i].Value = value
			return p
		}
	}
	return append(p, Field{Key: key, Value: value})
}

// Insert inserts the field before the field before; at the end if before is
// missing.
func (p Paragraph) Insert(before string, f Field) Paragraph {
	for i, g := range p {
		if strings.EqualFold(g.Key, before) {
			out := make(Paragraph, 0, len(p)+1)
			out = append(out, p[:i]...)
			out = append(out, f)
			return append(out, p[i:]...)
		}
	}
	return append(p, f)
}

// Delete removes the field key.
func (p Paragraph) Delete(key string) Paragraph {
	out := p[:0:0]
	for _, f := range p {
		if !strings.EqualFold(f.Key, key) {
			out = append(out, f)
		}
	}
	return out
}

// Clone returns a copy that can be changed independently.
func (p Paragraph) Clone() Paragraph {
	return append(Paragraph(nil), p...)
}

// String writes the paragraph: "Key: Value" per field; for a value that
// starts with "\n", "Key:" directly followed by the continuation lines.
func (p Paragraph) String() string {
	var b strings.Builder
	for _, f := range p {
		if strings.HasPrefix(f.Value, "\n") || f.Value == "" {
			fmt.Fprintf(&b, "%s:%s\n", f.Key, f.Value)
		} else {
			fmt.Fprintf(&b, "%s: %s\n", f.Key, f.Value)
		}
	}
	return b.String()
}

// Format writes paragraphs separated by one blank line each.
func Format(ps []Paragraph) string {
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.String())
	}
	return b.String()
}

// Parse reads the paragraphs of a control file. Continuation lines start
// with a space or tab; an empty line ends a paragraph. Lines starting with
// "#" are not comments: the files wdyapt reads have none, and dpkg rejects
// them in control as well.
func Parse(text string) ([]Paragraph, error) {
	var all []Paragraph
	var cur Paragraph
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for i, line := range strings.Split(text, "\n") {
		switch {
		case strings.TrimSpace(line) == "":
			if cur != nil {
				all = append(all, cur)
				cur = nil
			}
		case line[0] == ' ' || line[0] == '\t':
			if cur == nil {
				return nil, fmt.Errorf("line %d continues no field", i+1)
			}
			cur[len(cur)-1].Value += "\n" + line
		default:
			key, value, ok := strings.Cut(line, ":")
			if !ok || key == "" || strings.ContainsAny(key, " \t") {
				return nil, fmt.Errorf("line %d is no field: %q", i+1, line)
			}
			if _, dup := cur.Lookup(key); dup {
				return nil, fmt.Errorf("line %d repeats the field %s", i+1, key)
			}
			cur = append(cur, Field{Key: key, Value: strings.TrimRight(strings.TrimLeft(value, " \t"), " \t")})
		}
	}
	if cur != nil {
		all = append(all, cur)
	}
	return all, nil
}

// ParseOne reads a control file that contains exactly one paragraph.
func ParseOne(text string) (Paragraph, error) {
	ps, err := Parse(text)
	if err != nil {
		return nil, err
	}
	if len(ps) != 1 {
		return nil, fmt.Errorf("expected exactly one paragraph, found %d", len(ps))
	}
	return ps[0], nil
}

// Lines returns the lines of a multi-line value without the indentation and
// without empty lines, such as the checksums in Release.
func Lines(value string) []string {
	var out []string
	for line := range strings.SplitSeq(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
