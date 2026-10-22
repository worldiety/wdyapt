// Package knownhosts reads OpenSSH known_hosts files and checks host
// keys against them (R-ACCESS-HOST-KEY). It never adopts an unknown
// key.
package knownhosts

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/worldiety/wdyapt/internal/ssh"
)

// Line is an entry of a known_hosts file.
type Line struct {
	File     string
	Number   int
	Marker   string // "", "@revoked" or "@cert-authority"
	Patterns []string
	// hashed is set for "|1|salt|hash".
	salt, hash []byte
	Key        ssh.PublicKey
	KeyType    string
}

// DB holds the entries read.
type DB struct {
	Lines []Line
	// Notes are notices from reading, such as skipped lines.
	Notes []string
}

// ReadFile reads a known_hosts file.
func ReadFile(name string) (*DB, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f, name)
}

// Read reads known_hosts from r; name names the file in messages.
func Read(r io.Reader, name string) (*DB, error) {
	db := &DB{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		l := Line{File: name, Number: n}
		if strings.HasPrefix(fields[0], "@") {
			l.Marker, fields = fields[0], fields[1:]
			if l.Marker != "@revoked" && l.Marker != "@cert-authority" {
				db.Notes = append(db.Notes, fmt.Sprintf("%s:%d: unknown marker %s, line ignored", name, n, l.Marker))
				continue
			}
		}
		if len(fields) < 3 {
			db.Notes = append(db.Notes, fmt.Sprintf("%s:%d: incomplete line ignored", name, n))
			continue
		}
		hosts, typ, b64 := fields[0], fields[1], fields[2]
		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			db.Notes = append(db.Notes, fmt.Sprintf("%s:%d: broken key ignored", name, n))
			continue
		}
		l.KeyType = typ
		if l.Marker != "@cert-authority" {
			key, err := ssh.ParsePublicKey(blob)
			if err != nil {
				db.Notes = append(db.Notes, fmt.Sprintf("%s:%d: %v, line ignored", name, n, err))
				continue
			}
			l.Key = key
		}
		if strings.HasPrefix(hosts, "|1|") {
			parts := strings.Split(hosts, "|")
			if len(parts) != 4 {
				db.Notes = append(db.Notes, fmt.Sprintf("%s:%d: broken hashed host ignored", name, n))
				continue
			}
			salt, err1 := base64.StdEncoding.DecodeString(parts[2])
			hash, err2 := base64.StdEncoding.DecodeString(parts[3])
			if err1 != nil || err2 != nil {
				db.Notes = append(db.Notes, fmt.Sprintf("%s:%d: broken hashed host ignored", name, n))
				continue
			}
			l.salt, l.hash = salt, hash
		} else {
			l.Patterns = strings.Split(hosts, ",")
		}
		if l.Marker == "@cert-authority" {
			db.Notes = append(db.Notes, fmt.Sprintf("%s:%d: @cert-authority is not supported and ignored", name, n))
			continue
		}
		db.Lines = append(db.Lines, l)
	}
	return db, sc.Err()
}

// HostName is the name of a target in known_hosts: host for port 22,
// otherwise [host]:port.
func HostName(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if port == "22" {
		return host
	}
	return "[" + host + "]:" + port
}

// matches reports whether the line applies to name.
func (l *Line) matches(name string) bool {
	if l.hash != nil {
		mac := hmac.New(sha1.New, l.salt)
		mac.Write([]byte(name))
		return hmac.Equal(mac.Sum(nil), l.hash)
	}
	matched := false
	for _, p := range l.Patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		if wildMatch(strings.ToLower(p), strings.ToLower(name)) {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}

// wildMatch is OpenSSH's pattern matching: "*" and "?", everything else
// literal.
func wildMatch(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for i := len(s); i >= 0; i-- {
				if wildMatch(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			if s == "" || p[0] != s[0] {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return s == ""
}

// Result tells what known_hosts knows about a key.
type Result struct {
	// Line is the confirming line if the key is known.
	Line *Line
	// Mismatch are lines with a different key of the same type.
	Mismatch []*Line
	// Revoked is the line that revokes the key.
	Revoked *Line
	// KnownTypes are the key types known for the host.
	KnownTypes []string
}

// Lookup looks up what the file says about the key key of the target addr.
func (db *DB) Lookup(addr string, key ssh.PublicKey) Result {
	name := HostName(addr)
	var res Result
	blob := key.Marshal()
	for i := range db.Lines {
		l := &db.Lines[i]
		if !l.matches(name) {
			continue
		}
		same := bytes.Equal(l.Key.Marshal(), blob)
		if l.Marker == "@revoked" {
			if same {
				res.Revoked = l
			}
			continue
		}
		res.KnownTypes = append(res.KnownTypes, l.Key.Type())
		switch {
		case same && res.Line == nil:
			res.Line = l
		case !same && l.Key.Type() == key.Type():
			res.Mismatch = append(res.Mismatch, l)
		}
	}
	return res
}

// KnownTypes returns the key types known for addr, so that the client
// prefers their algorithms.
func (db *DB) KnownTypes(addr string) []string {
	name := HostName(addr)
	var out []string
	for i := range db.Lines {
		l := &db.Lines[i]
		if l.Marker == "" && l.matches(name) {
			out = append(out, l.Key.Type())
		}
	}
	return out
}

// Callback checks host keys against db. confirmed reports the
// confirming line, for example for "matches known_hosts line 3".
func (db *DB) Callback(confirmed func(l *Line)) ssh.HostKeyCallback {
	return func(addr string, key ssh.PublicKey) error {
		res := db.Lookup(addr, key)
		fp := ssh.Fingerprint(key)
		switch {
		case res.Revoked != nil:
			return &ssh.HostKeyError{Addr: addr, Key: key, Msg: fmt.Sprintf("the host key %s of %s is revoked in %s:%d", fp, HostName(addr), res.Revoked.File, res.Revoked.Number)}
		case res.Line != nil:
			if confirmed != nil {
				confirmed(res.Line)
			}
			return nil
		case len(res.Mismatch) > 0:
			m := res.Mismatch[0]
			return &ssh.HostKeyError{Addr: addr, Key: key, Msg: fmt.Sprintf("WARNING: the %s host key of %s is %s, but %s:%d expects %s; possible man-in-the-middle attack. If the server's key really changed, confirm the new one over a second channel and update the file", key.Type(), HostName(addr), fp, m.File, m.Number, ssh.Fingerprint(m.Key))}
		}
		return &ssh.HostKeyError{Addr: addr, Key: key, Msg: fmt.Sprintf("the host %s is not in the known_hosts file (its %s key is %s); fetch its keys with \"wdyapt remote hostkey %s\", compare the fingerprints over a second channel, and add the line", HostName(addr), key.Type(), fp, hostArg(addr))}
	}
}

// Fingerprints checks against given fingerprints instead of known_hosts.
func Fingerprints(fps []string) ssh.HostKeyCallback {
	return func(addr string, key ssh.PublicKey) error {
		fp := ssh.Fingerprint(key)
		for _, want := range fps {
			if strings.TrimSpace(want) == fp {
				return nil
			}
		}
		return &ssh.HostKeyError{Addr: addr, Key: key, Msg: fmt.Sprintf("the %s host key of %s is %s, which is none of the fingerprints given with --host-key; possible man-in-the-middle attack", key.Type(), HostName(addr), fp)}
	}
}

func hostArg(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "22" {
		return host
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return host
	}
	return host + ":" + port
}

// FormatLine writes a line for known_hosts.
func FormatLine(addr string, key ssh.PublicKey) string {
	return HostName(addr) + " " + ssh.AuthorizedKey(key)
}
