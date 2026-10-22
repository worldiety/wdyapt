// Package sshtest is an SSH server for tests only: it uses the server
// side of the same building blocks as the client and can be configured
// to demonstrate errors and attacks.
package sshtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"net"
	"sync"
	"testing"

	"github.com/worldiety/wdyapt/internal/ssh"
)

// Options configure the server.
type Options struct {
	Config ssh.ServerConfig
	// Auth lets clients in; without it the connection ends after the key
	// exchange when the client leaves.
	Auth *ssh.ServerAuth
	// Subsystems serve subsystems such as "sftp" on a channel.
	Subsystems map[string]func(ch *ssh.Channel)
	// Raw runs after the key exchange instead of authentication and channels.
	Raw func(c *ssh.ServerConn)
}

// Server accepts connections on 127.0.0.1.
type Server struct {
	Addr string
	Opts Options

	ln     net.Listener
	wg     sync.WaitGroup
	mu     sync.Mutex
	errs   []error
	logins []string
}

// Start starts the server and stops it at the end of the test.
func Start(t testing.TB, opts Options) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Config.HostKeys) == 0 {
		opts.Config.HostKeys = HostKeys(t)
	}
	s := &Server{Addr: ln.Addr().String(), Opts: opts, ln: ln}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *Server) fail(err error) {
	s.mu.Lock()
	s.errs = append(s.errs, err)
	s.mu.Unlock()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer nc.Close()
			cfg := s.Opts.Config
			c, err := ssh.NewServerConn(nc, &cfg)
			if err != nil {
				s.fail(err)
				return
			}
			defer c.Close()
			switch {
			case s.Opts.Raw != nil:
				s.Opts.Raw(c)
			case s.Opts.Auth != nil:
				s.session(c)
			default:
				for {
					if _, err := c.ReadPacket(); err != nil {
						return
					}
				}
			}
		}()
	}
}

// session authenticates the client and serves its channels.
func (s *Server) session(c *ssh.ServerConn) {
	user, method, err := c.Authenticate(*s.Opts.Auth)
	if err != nil {
		s.fail(err)
		return
	}
	s.mu.Lock()
	s.logins = append(s.logins, user+" "+method)
	s.mu.Unlock()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		ch, err := c.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer ch.Close()
			for req := range ch.Requests {
				if req.Type != "subsystem" || len(req.Payload) < 4 {
					req.Reply(false)
					continue
				}
				name := string(req.Payload[4:][:min(int(binary.BigEndian.Uint32(req.Payload)), len(req.Payload)-4)])
				h := s.Opts.Subsystems[name]
				if h == nil {
					req.Reply(false)
					continue
				}
				req.Reply(true)
				h(ch)
				return
			}
		}()
	}
}

// Errors returns the errors of the connections on the server side.
func (s *Server) Errors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.errs...)
}

// Logins lists the successful logins as "user method".
func (s *Server) Logins() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.logins...)
}

// HostKeys generates one host key each of ed25519, ecdsa P-256, P-384,
// P-521 and RSA 2048 (the latter once per test run, because it is slow).
func HostKeys(t testing.TB) []ssh.Signer {
	t.Helper()
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := []crypto.Signer{ed, ecdsaKey(t, elliptic.P256()), ecdsaKey(t, elliptic.P384()), ecdsaKey(t, elliptic.P521()), RSAKey(t)}
	var out []ssh.Signer
	for _, k := range keys {
		s, err := ssh.NewSigner(k)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func ecdsaKey(t testing.TB, c elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	rsaOnce sync.Once
	rsaPriv *rsa.PrivateKey
	rsaErr  error
)

// RSAKey returns a 2048-bit RSA key, once per test run.
func RSAKey(t testing.TB) *rsa.PrivateKey {
	rsaOnce.Do(func() { rsaPriv, rsaErr = rsa.GenerateKey(rand.Reader, 2048) })
	if rsaErr != nil {
		t.Fatal(rsaErr)
	}
	return rsaPriv
}
