package main

import (
	"strings"
	"testing"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/ssh"
	"github.com/worldiety/wdyapt/internal/ssh/knownhosts"
	"github.com/worldiety/wdyapt/internal/ssh/sshtest"
	reqaccess "github.com/worldiety/wdyapt/requirements/fun/access"
)

// remote hostkey writes one line for known_hosts per key type, and the
// fingerprints with the warning to Stderr.
func TestHostKeyCommand(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{})
	r := wdyapt(t, nil, "remote", "hostkey", srv.Addr)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines:\n%s", r.stdout)
	}
	db, err := knownhosts.Read(strings.NewReader(r.stdout), "out")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range srv.Opts.Config.HostKeys {
		pub := k.PublicKey()
		if pub.Type() == ssh.KeyECDSA384 || pub.Type() == ssh.KeyECDSA521 {
			continue
		}
		if err := db.Callback(nil)(srv.Addr, pub); err != nil {
			t.Errorf("%s: %v", pub.Type(), err)
		}
		if !strings.Contains(r.stderr, ssh.Fingerprint(pub)) {
			t.Errorf("stderr lacks the fingerprint of %s", pub.Type())
		}
	}
	if !strings.Contains(r.stderr, "second channel") {
		t.Errorf("no warning: %s", r.stderr)
	}
	only := wdyapt(t, nil, "remote", "hostkey", "--type", "ed25519", srv.Addr)
	if strings.Count(only.stdout, "\n") != 1 || !strings.Contains(only.stdout, "ssh-ed25519 ") {
		t.Errorf("--type ed25519: %s", only.stdout)
	}
	if bad := wdyapt(t, nil, "remote", "hostkey", "--type", "dsa", srv.Addr); bad.code != 2 {
		t.Errorf("--type dsa: exit %d", bad.code)
	}
	spec.Verified(t, reqaccess.RAccessHostKey)
}
