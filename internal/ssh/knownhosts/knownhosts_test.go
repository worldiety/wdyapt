package knownhosts

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/ssh"
	reqaccess "github.com/worldiety/wdyapt/requirements/fun/access"
)

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s.PublicKey()
}

func hashed(name string) string {
	salt := []byte("0123456789abcdef0123")
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(name))
	return "|1|" + base64.StdEncoding.EncodeToString(salt) + "|" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestKnownHostsMatching(t *testing.T) {
	a, b, c := newKey(t), newKey(t), newKey(t)
	text := fmt.Sprintf(`# comment
sftp.example.com,10.0.0.1 %s
[sftp.example.com]:2222 %s
*.example.org,!bad.example.org %s
@cert-authority *.example.net %s
`, ssh.AuthorizedKey(a), ssh.AuthorizedKey(b), ssh.AuthorizedKey(c), ssh.AuthorizedKey(c))
	db, err := Read(strings.NewReader(text), "known_hosts")
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Notes) != 1 || !strings.Contains(db.Notes[0], "cert-authority") {
		t.Errorf("notes = %v", db.Notes)
	}
	var confirmed *Line
	check := db.Callback(func(l *Line) { confirmed = l })
	for _, tc := range []struct {
		addr string
		key  ssh.PublicKey
		line int
	}{
		{"sftp.example.com:22", a, 2},
		{"10.0.0.1:22", a, 2},
		{"SFTP.example.com:22", a, 2},
		{"sftp.example.com:2222", b, 3},
		{"repo.example.org:22", c, 4},
	} {
		confirmed = nil
		if err := check(tc.addr, tc.key); err != nil || confirmed == nil || confirmed.Number != tc.line {
			t.Errorf("%s: %v line %v", tc.addr, err, confirmed)
		}
	}
	for _, tc := range []struct {
		addr string
		key  ssh.PublicKey
		want string
	}{
		{"sftp.example.com:22", b, "possible man-in-the-middle"},
		{"sftp.example.com:2222", a, "possible man-in-the-middle"},
		{"bad.example.org:22", c, "not in the known_hosts file"},
		{"other.example.com:22", a, "wdyapt remote hostkey other.example.com"},
		{"other.example.com:2200", a, "wdyapt remote hostkey other.example.com:2200"},
	} {
		err := check(tc.addr, tc.key)
		var hk *ssh.HostKeyError
		if !errors.As(err, &hk) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.addr, err)
		}
	}
	spec.Verified(t, reqaccess.RAccessHostKey)
}

func TestHashedHosts(t *testing.T) {
	a := newKey(t)
	db, err := Read(strings.NewReader(hashed("[sftp.example.com]:2222")+" "+ssh.AuthorizedKey(a)+"\n"), "kh")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Callback(nil)("sftp.example.com:2222", a); err != nil {
		t.Errorf("hashed host: %v", err)
	}
	if err := db.Callback(nil)("sftp.example.com:22", a); err == nil {
		t.Error("hashed host matched another port")
	}
	spec.Verified(t, reqaccess.RAccessHostKey)
}

func TestUnknownHostRefused(t *testing.T) {
	a := newKey(t)
	db, _ := Read(strings.NewReader("@revoked * "+ssh.AuthorizedKey(a)+"\nhost "+ssh.AuthorizedKey(a)+"\n"), "kh")
	if err := db.Callback(nil)("host:22", a); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("revoked key: %v", err)
	}
	empty, _ := Read(strings.NewReader(""), "kh")
	if err := empty.Callback(nil)("host:22", a); err == nil {
		t.Error("unknown host accepted")
	}
	fp := Fingerprints([]string{"SHA256:nope", ssh.Fingerprint(a)})
	if err := fp("host:22", a); err != nil {
		t.Errorf("fingerprint: %v", err)
	}
	if err := Fingerprints([]string{"SHA256:nope"})("host:22", a); err == nil {
		t.Error("wrong fingerprint accepted")
	}
	if FormatLine("h:22", a) != "h "+ssh.AuthorizedKey(a) || FormatLine("h:2222", a) != "[h]:2222 "+ssh.AuthorizedKey(a) {
		t.Error("FormatLine")
	}
	spec.Verified(t, reqaccess.RAccessHostKey)
}
