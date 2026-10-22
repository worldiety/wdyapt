package ssh

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/dec"
)

var (
	hostKeysOnce sync.Once
	hostKeys     []Signer
)

// testHostKeys are host keys of all types, once per test run.
func testHostKeys(t *testing.T) []Signer {
	t.Helper()
	hostKeysOnce.Do(func() {
		_, ed, _ := ed25519.GenerateKey(rand.Reader)
		p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		r, _ := rsa.GenerateKey(rand.Reader, 2048)
		for _, k := range []crypto.Signer{ed, p256, p384, p521, r} {
			s, err := NewSigner(k)
			if err != nil {
				panic(err)
			}
			hostKeys = append(hostKeys, s)
		}
	})
	return hostKeys
}

// pair connects client and server over a TCP connection on localhost.
func pair(t *testing.T, ccfg *ClientConfig, scfg *ServerConfig) (*Client, *ServerConn, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if scfg.HostKeys == nil {
		scfg.HostKeys = testHostKeys(t)
	}
	if ccfg.HostKey == nil {
		ccfg.HostKey = func(string, PublicKey) error { return nil }
	}
	ccfg.rawTransport = true
	type result struct {
		s   *ServerConn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		s, err := NewServerConn(nc, scfg)
		if err != nil {
			nc.Close()
		}
		ch <- result{s, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, cerr := Dial(ctx, ln.Addr().String(), ccfg)
	r := <-ch
	if cerr != nil {
		if r.s != nil {
			r.s.Close()
		}
		return nil, nil, cerr
	}
	if r.err != nil {
		c.Close()
		return nil, nil, r.err
	}
	t.Cleanup(func() { c.Close(); r.s.Close() })
	return c, r.s, nil
}

// roundTrip sends messages in both directions and checks them.
func roundTrip(t *testing.T, c *Client, s *ServerConn, n, size int) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			p, err := s.ReadPacket()
			if err != nil {
				done <- err
				return
			}
			if err := s.WritePacket(p); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < n; i++ {
		msg := append([]byte{200}, bytes.Repeat([]byte{byte(i)}, size)...)
		if err := c.writePacket(msg); err != nil {
			t.Fatal(err)
		}
		got, err := c.readPacket()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("message %d changed", i)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKexAlgorithms(t *testing.T) {
	for _, kex := range defaultKex {
		t.Run(kex, func(t *testing.T) {
			c, s, err := pair(t, &ClientConfig{Config: Config{KexAlgorithms: []string{kex}}}, &ServerConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if c.Algorithms.Kex != kex || s.Algorithms.Kex != kex || !c.Algorithms.StrictKex {
				t.Errorf("negotiated %+v", c.Algorithms)
			}
			roundTrip(t, c, s, 3, 100)
		})
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

func TestCiphers(t *testing.T) {
	for _, cipher := range defaultCiphers {
		for _, mac := range defaultMACs {
			if cipherSpecs[cipher].aead && mac != defaultMACs[0] {
				continue
			}
			t.Run(cipher+"/"+mac, func(t *testing.T) {
				c, s, err := pair(t, &ClientConfig{Config: Config{Ciphers: []string{cipher}, MACs: []string{mac}}}, &ServerConfig{})
				if err != nil {
					t.Fatal(err)
				}
				if c.Algorithms.CipherClientServer != cipher || (!cipherSpecs[cipher].aead && c.Algorithms.MACClientServer != mac) {
					t.Errorf("negotiated %+v", c.Algorithms)
				}
				for _, size := range []int{0, 1, 15, 16, 17, 1000, 32 << 10} {
					roundTrip(t, c, s, 2, size)
				}
			})
		}
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

func TestHostKeyAlgorithms(t *testing.T) {
	for _, algo := range defaultHostKeyAlgos {
		t.Run(algo, func(t *testing.T) {
			var seen PublicKey
			c, _, err := pair(t, &ClientConfig{Config: Config{HostKeyAlgorithms: []string{algo}}, HostKey: func(_ string, k PublicKey) error {
				seen = k
				return nil
			}}, &ServerConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if c.Algorithms.HostKey != algo || seen == nil || seen.Type() != keyTypeOf(algo) {
				t.Errorf("negotiated %s, key %v", c.Algorithms.HostKey, seen)
			}
		})
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// After a few bytes both sides exchange new keys, initiated by the client
// as well as by the server; the data arrives unchanged.
func TestRekey(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			ccfg, scfg := &ClientConfig{}, &ServerConfig{}
			if side == "client" {
				ccfg.RekeyBytes = 64 << 10
			} else {
				scfg.RekeyBytes = 64 << 10
			}
			c, s, err := pair(t, ccfg, scfg)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip(t, c, s, 40, 16<<10)
			if c.Rekeys() < 3 || s.Rekeys() < 3 {
				t.Errorf("rekeys: client %d, server %d", c.Rekeys(), s.Rekeys())
			}
		})
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// Strict kex: a packet that an attacker injects before NEWKEYS
// (Terrapin) aborts the exchange.
func TestStrictKexRejectsInjectedPackets(t *testing.T) {
	scfg := &ServerConfig{Config: Config{injectBeforeNewKeys: newBuilder(msgIgnore).text("terrapin").b}}
	_, _, err := pair(t, &ClientConfig{}, scfg)
	if err == nil || !strings.Contains(err.Error(), "expected NEWKEYS") {
		t.Fatalf("injected IGNORE accepted: %v", err)
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// A rejected host key ends the connection before anything else.
func TestRejectedHostKeyStops(t *testing.T) {
	refuse := errors.New("not the expected key")
	_, _, err := pair(t, &ClientConfig{HostKey: func(string, PublicKey) error { return &HostKeyError{Msg: refuse.Error()} }}, &ServerConfig{})
	var hk *HostKeyError
	if !errors.As(err, &hk) {
		t.Fatalf("err = %v", err)
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// A byte altered in transit is caught by the MAC or tag.
func TestTamperedPacketIsRejected(t *testing.T) {
	for _, cipher := range []string{"aes256-gcm@openssh.com", "aes128-ctr"} {
		for _, mac := range []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"} {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			var flip sync.Once
			go func() {
				nc, err := ln.Accept()
				if err != nil {
					return
				}
				s, err := NewServerConn(&corrupter{Conn: nc, after: 4000, flip: &flip}, &ServerConfig{HostKeys: testHostKeys(t)})
				if err == nil {
					for {
						if _, err := s.ReadPacket(); err != nil {
							return
						}
					}
				}
			}()
			c, err := Dial(context.Background(), ln.Addr().String(), &ClientConfig{Config: Config{Ciphers: []string{cipher}, MACs: []string{mac}}, HostKey: func(string, PublicKey) error { return nil }, rawTransport: true})
			if err != nil {
				t.Fatal(err)
			}
			var werr error
			for i := 0; i < 50 && werr == nil; i++ {
				werr = c.writePacket(append([]byte{200}, make([]byte, 500)...))
				time.Sleep(time.Millisecond)
			}
			_, rerr := c.readPacket()
			if rerr == nil {
				t.Errorf("%s/%s: no error after tampering", cipher, mac)
			}
			c.Close()
			ln.Close()
		}
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// corrupter alters a byte after after bytes have been read.
type corrupter struct {
	net.Conn
	after int
	n     int
	flip  *sync.Once
}

func (c *corrupter) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.n+n > c.after {
		c.flip.Do(func() { p[c.after-c.n] ^= 0x40 })
	}
	c.n += n
	return n, err
}

// Lines before the identification are skipped; SSH 1 is rejected.
func TestVersionExchange(t *testing.T) {
	for _, tc := range []struct {
		server string
		ok     bool
	}{
		{"Welcome\r\nto the server\r\nSSH-2.0-OpenSSH_9.6\r\n", true},
		{"SSH-1.99-OpenSSH_3\r\n", true},
		{"SSH-1.5-old\r\n", false},
		{strings.Repeat("noise\r\n", 40) + "SSH-2.0-x\r\n", false},
	} {
		a, b := net.Pipe()
		go io.Copy(io.Discard, b)
		go io.WriteString(b, tc.server)
		tr := newTransport(a, true, &Config{})
		err := tr.exchangeVersions()
		if (err == nil) != tc.ok {
			t.Errorf("%q: %v", tc.server, err)
		}
		a.Close()
		b.Close()
	}
	spec.Verified(t, dec.RDecSshAndSftpInProcess)
}

// The DH groups are the primes from RFC 3526.
func TestDHGroups(t *testing.T) {
	for _, g := range []struct {
		p    interface{ BitLen() int }
		bits int
	}{{group14, 2048}, {group16, 4096}} {
		if g.p.BitLen() != g.bits {
			t.Errorf("group with %d bits, want %d", g.p.BitLen(), g.bits)
		}
	}
	if !group14.ProbablyPrime(20) || !group16.ProbablyPrime(20) {
		t.Error("a group is not prime")
	}
}

// Without a common algorithm, the error names what both sides offer.
func TestNoCommonAlgorithm(t *testing.T) {
	_, _, err := pair(t, &ClientConfig{Config: Config{Ciphers: []string{"aes128-ctr"}}}, &ServerConfig{Config: Config{Ciphers: []string{"aes256-gcm@openssh.com"}}})
	if err == nil || !strings.Contains(err.Error(), "no common cipher") {
		t.Errorf("err = %v", err)
	}
}
