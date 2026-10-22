package ssh_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/internal/ssh"
	"github.com/worldiety/wdyapt/internal/ssh/agent"
	"github.com/worldiety/wdyapt/internal/ssh/sshtest"
	"github.com/worldiety/wdyapt/requirements/dec"
	reqaccess "github.com/worldiety/wdyapt/requirements/fun/access"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

const secretPassword = `p"a$s w'o\rd!;&|`

func readKey(t *testing.T, name string) ssh.Signer {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s
}

func authorized(keys ...ssh.PublicKey) func(string, ssh.PublicKey) bool {
	return func(user string, k ssh.PublicKey) bool {
		for _, a := range keys {
			if bytes.Equal(a.Marshal(), k.Marshal()) {
				return user == "deploy"
			}
		}
		return false
	}
}

func dial(t *testing.T, srv *sshtest.Server, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := ssh.Dial(ctx, srv.Addr, &ssh.ClientConfig{User: "deploy", Auth: auth, HostKey: func(string, ssh.PublicKey) error { return nil }})
	if err == nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

func passwordAuth() *ssh.ServerAuth {
	return &ssh.ServerAuth{Password: func(user string, pw []byte) bool { return user == "deploy" && string(pw) == secretPassword }}
}

// Authentication with a password; a wrong password names the attempts
// and the allowed methods, never the password.
func TestPasswordAuth(t *testing.T) {
	srv := sshtest.Start(t, sshtest.Options{Auth: passwordAuth()})
	c, err := dial(t, srv, ssh.Password([]byte(secretPassword)))
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthMethod != "password" {
		t.Errorf("method %s", c.AuthMethod)
	}
	_, err = dial(t, srv, ssh.Password([]byte("wrong "+secretPassword)))
	var ae *ssh.AuthError
	if !errors.As(err, &ae) || !strings.Contains(err.Error(), "tried password; the server allows password") {
		t.Fatalf("wrong password: %v", err)
	}
	if strings.Contains(err.Error(), secretPassword) || strings.Contains(err.Error(), "wrong") {
		t.Errorf("the error shows the password: %v", err)
	}
	spec.Verified(t, reqaccess.RAccessLogin, nfr.RNfrConfidentialCredentials)
}

// keyboard-interactive answers the single hidden prompt with the
// password.
func TestKeyboardInteractive(t *testing.T) {
	auth := passwordAuth()
	auth.KeyboardInteractive = true
	srv := sshtest.Start(t, sshtest.Options{Auth: &ssh.ServerAuth{KeyboardInteractive: true, Password: auth.Password}})
	c, err := dial(t, srv, ssh.KeyboardInteractive([]byte(secretPassword)))
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthMethod != "keyboard-interactive" {
		t.Errorf("method %s", c.AuthMethod)
	}
	if _, err := dial(t, srv, ssh.KeyboardInteractive([]byte("nope"))); err == nil {
		t.Error("wrong answer accepted")
	}
	spec.Verified(t, reqaccess.RAccessLogin)
}

// Key files in OpenSSH, PKCS#1 and PKCS#8 format authenticate; RSA signs
// with rsa-sha2-512. Encrypted keys are rejected with a way out.
func TestPublicKeyFile(t *testing.T) {
	var keys []ssh.Signer
	for _, name := range []string{"k_ed25519", "k_ecdsa", "k_rsa", "k_rsa_pem", "k_ecdsa_pkcs8"} {
		k := readKey(t, name)
		pub, _ := os.ReadFile(filepath.Join("testdata", name+".pub"))
		if !strings.HasPrefix(string(pub), ssh.AuthorizedKey(k.PublicKey())) {
			t.Errorf("%s: public key differs from ssh-keygen's", name)
		}
		keys = append(keys, k)
	}
	var pubs []ssh.PublicKey
	for _, k := range keys {
		pubs = append(pubs, k.PublicKey())
	}
	srv := sshtest.Start(t, sshtest.Options{Auth: &ssh.ServerAuth{PublicKey: authorized(pubs...)}})
	for i, k := range keys {
		c, err := dial(t, srv, ssh.PublicKeys("identity file", k))
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		if !strings.HasPrefix(c.AuthMethod, "publickey (identity file, "+k.PublicKey().Type()) {
			t.Errorf("method %s", c.AuthMethod)
		}
	}
	other := readKey(t, "k_ed25519")
	srv2 := sshtest.Start(t, sshtest.Options{Auth: &ssh.ServerAuth{PublicKey: authorized(keys[1].PublicKey()), Password: passwordAuth().Password}})
	// The first key does not fit, the second does; after that there would
	// still be the password.
	c, err := dial(t, srv2, ssh.PublicKeys("agent", other, keys[1]), ssh.Password([]byte(secretPassword)))
	if err != nil || !strings.Contains(c.AuthMethod, "ecdsa") {
		t.Fatalf("second key: %v %s", err, c.AuthMethod)
	}
	data, _ := os.ReadFile(filepath.Join("testdata", "k_encrypted"))
	if _, err := ssh.ParsePrivateKey(data); err == nil || !strings.Contains(err.Error(), "ssh-agent") {
		t.Errorf("encrypted key: %v", err)
	}
	spec.Verified(t, reqaccess.RAccessLogin)
}

// testAgent is an ssh-agent with keys in memory.
func testAgent(t *testing.T, keys ...ssh.Signer) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveAgent(conn, keys)
		}
	}()
	return sock
}

func serveAgent(conn net.Conn, keys []ssh.Signer) {
	defer conn.Close()
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	for {
		var head [4]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint32(head[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		var resp []byte
		switch msg[0] {
		case 11:
			resp = binary.BigEndian.AppendUint32([]byte{12}, uint32(len(keys)))
			for _, k := range keys {
				resp = append(resp, str(k.PublicKey().Marshal())...)
				resp = append(resp, str([]byte("test key"))...)
			}
		case 13:
			r := msg[1:]
			n := binary.BigEndian.Uint32(r)
			blob := r[4 : 4+n]
			r = r[4+n:]
			n = binary.BigEndian.Uint32(r)
			data := r[4 : 4+n]
			flags := binary.BigEndian.Uint32(r[4+n:])
			resp = []byte{5}
			for _, k := range keys {
				if !bytes.Equal(k.PublicKey().Marshal(), blob) {
					continue
				}
				algo := k.PublicKey().Type()
				if algo == ssh.KeyRSA {
					algo = map[uint32]string{2: ssh.SigRSASHA256, 4: ssh.SigRSASHA512}[flags]
				}
				if sig, err := k.Sign(data, algo); err == nil {
					resp = append([]byte{14}, str(sig)...)
				}
			}
		default:
			resp = []byte{5}
		}
		conn.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(resp))), resp...))
	}
}

// Through the ssh-agent: list keys and have them sign, including RSA with
// rsa-sha2-512.
func TestAgent(t *testing.T) {
	ed, rsa := readKey(t, "k_ed25519"), readKey(t, "k_rsa")
	sock := testAgent(t, ed, rsa)
	ag, err := agent.Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ag.Close()
	signers, err := ag.Signers()
	if err != nil || len(signers) != 2 {
		t.Fatalf("signers: %v %d", err, len(signers))
	}
	srv := sshtest.Start(t, sshtest.Options{Auth: &ssh.ServerAuth{PublicKey: authorized(rsa.PublicKey())}})
	c, err := dial(t, srv, ssh.PublicKeys("ssh-agent", signers...))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.AuthMethod, "ssh-agent, ssh-rsa") {
		t.Errorf("method %s", c.AuthMethod)
	}
	spec.Verified(t, reqaccess.RAccessLogin)
}

// A channel transfers megabytes in both directions with windows of 2 MiB
// and packets of 32 KiB, even while the keys change several times.
func TestChannelWindowsAndRekey(t *testing.T) {
	echo := func(ch *ssh.Channel) {
		io.Copy(ch, ch)
		ch.CloseWrite()
	}
	srv := sshtest.Start(t, sshtest.Options{
		Config:     ssh.ServerConfig{Config: ssh.Config{RekeyBytes: 1 << 20}},
		Auth:       passwordAuth(),
		Subsystems: map[string]func(*ssh.Channel){"echo": echo},
	})
	ctx := context.Background()
	c, err := ssh.Dial(ctx, srv.Addr, &ssh.ClientConfig{Config: ssh.Config{RekeyBytes: 3 << 20}, User: "deploy",
		Auth: []ssh.AuthMethod{ssh.Password([]byte(secretPassword))}, HostKey: func(string, ssh.PublicKey) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Subsystem(ctx, "missing"); err == nil {
		t.Error("unknown subsystem accepted")
	}
	ch, err := c.Subsystem(ctx, "echo")
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 12<<20)
	rand.Read(data)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ch.Write(data)
		ch.CloseWrite()
	}()
	h := sha256.New()
	n, err := io.Copy(h, ch)
	wg.Wait()
	want := sha256.Sum256(data)
	if err != nil || n != int64(len(data)) || !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatalf("echo: %d bytes, %v", n, err)
	}
	if c.Rekeys() < 3 {
		t.Errorf("only %d rekeys", c.Rekeys())
	}
	ch.Close()
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// Fingerprints like OpenSSH: SHA256 over the blob, Base64 without padding.
func TestFingerprint(t *testing.T) {
	k := readKey(t, "k_ed25519")
	sum := sha256.Sum256(k.PublicKey().Marshal())
	if ssh.Fingerprint(k.PublicKey()) != "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]) {
		t.Error("fingerprint")
	}
}
