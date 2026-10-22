package debian

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// ValidName checks a package name according to Debian Policy 5.6.1:
// lowercase letters, digits, "+", "-" and ".", at least two characters,
// starting with a letter or a digit.
func ValidName(name string) error {
	if !packageName.MatchString(name) {
		return fmt.Errorf("invalid package name %q: use at least two of a-z, 0-9, '+', '-', '.', starting with a letter or digit", name)
	}
	return nil
}

// Version is a Debian version [epoch:]upstream[-revision].
type Version struct {
	Epoch    int
	Upstream string
	Revision string
}

var (
	epochPattern    = regexp.MustCompile(`^[0-9]+$`)
	revisionPattern = regexp.MustCompile(`^[A-Za-z0-9.+~]+$`)
)

// ParseVersion reads and checks a version according to Debian Policy 5.6.12.
func ParseVersion(s string) (Version, error) {
	bad := func(why string) (Version, error) {
		return Version{}, fmt.Errorf("invalid version %q: %s", s, why)
	}
	if s == "" {
		return bad("empty")
	}
	var v Version
	rest := s
	e, r, hasEpoch := strings.Cut(s, ":")
	if hasEpoch {
		if !epochPattern.MatchString(e) {
			return bad("the epoch before ':' must be a number")
		}
		n, err := strconv.Atoi(e)
		if err != nil {
			return bad("the epoch is too large")
		}
		v.Epoch, rest = n, r
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		v.Upstream, v.Revision = rest[:i], rest[i+1:]
		if !revisionPattern.MatchString(v.Revision) {
			return bad("the revision after the last '-' may only contain A-Z, a-z, 0-9, '.', '+' and '~'")
		}
	} else {
		v.Upstream = rest
	}
	if v.Upstream == "" || v.Upstream[0] < '0' || v.Upstream[0] > '9' {
		return bad("the upstream version must start with a digit")
	}
	for _, c := range v.Upstream {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', strings.ContainsRune(".+~", c):
		case c == '-' && v.Revision != "":
		case c == ':' && hasEpoch:
		default:
			return bad(fmt.Sprintf("the upstream version may not contain %q", c))
		}
	}
	return v, nil
}

// String writes the version back as it was read.
func (v Version) String() string {
	s := v.Upstream
	if v.Revision != "" {
		s += "-" + v.Revision
	}
	if v.Epoch != 0 {
		s = strconv.Itoa(v.Epoch) + ":" + s
	}
	return s
}

// WithoutEpoch is the version as it appears in file names.
func (v Version) WithoutEpoch() string {
	s := v.Upstream
	if v.Revision != "" {
		s += "-" + v.Revision
	}
	return s
}

// CompareVersions compares two versions by the rules of dpkg: the epoch
// numerically, then upstream and revision with verrevcmp. "~" sorts before
// everything else, even before the end. Invalid versions are split as well
// as possible so that foreign lists can be sorted too.
func CompareVersions(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitVersion(v string) (epoch int, upstream, revision string) {
	if e, rest, ok := strings.Cut(v, ":"); ok {
		epoch, _ = strconv.Atoi(e)
		v = rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// verrevcmp is the comparison of the same name from dpkg
// (lib/dpkg/version.c): alternating sections without and with digits.
// Without digits every character counts on its own: "~" before the end, the
// end before letters, letters before all other characters. Digit sections
// count as numbers.
func verrevcmp(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	order := func(c byte) int {
		switch {
		case digit(c), c == 0:
			return 0
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
			return int(c)
		case c == '~':
			return -1
		default:
			return int(c) + 256
		}
	}
	sign := func(n int) int {
		switch {
		case n < 0:
			return -1
		case n > 0:
			return 1
		}
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !digit(a[i])) || (j < len(b) && !digit(b[j])) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		first := 0
		for digit(at(a, i)) && digit(at(b, j)) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if digit(at(a, i)) {
			return 1
		}
		if digit(at(b, j)) {
			return -1
		}
		if first != 0 {
			return sign(first)
		}
	}
	return 0
}

// PoolPath is the path of a package in the pool of a repository:
// pool/<component>/<prefix>/<source>/<file>. source is the field Source
// without "(version)", or the package name if it is missing; prefix is its
// first letter, or the first four for names starting with "lib".
func PoolPath(component, pkg, source, file string) string {
	if s, _, _ := strings.Cut(strings.TrimSpace(source), " "); s != "" {
		source = s
	} else {
		source = pkg
	}
	prefix := source[:1]
	if strings.HasPrefix(source, "lib") && len(source) > 3 {
		prefix = source[:4]
	}
	return "pool/" + component + "/" + prefix + "/" + source + "/" + file
}
