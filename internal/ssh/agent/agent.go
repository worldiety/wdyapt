// Package agent talks to a running ssh-agent over its Unix socket
// (OpenSSH's PROTOCOL.agent): it lists keys and has data signed. The
// private key never leaves the agent.
package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/worldiety/wdyapt/internal/ssh"
)

// Messages of the agent protocol.
const (
	msgFailure           = 5
	msgRequestIdentities = 11
	msgIdentitiesAnswer  = 12
	msgSignRequest       = 13
	msgSignResponse      = 14

	flagRSASHA256 = 2
	flagRSASHA512 = 4

	maxMessage = 256 << 10
)

// Client is a connection to the agent.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
}

// Dial connects to the socket socket, for example from SSH_AUTH_SOCK.
func Dial(socket string) (*Client, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// NewClient talks over an existing connection.
func NewClient(conn net.Conn) *Client { return &Client{conn: conn} }

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) call(req []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	msg := binary.BigEndian.AppendUint32(nil, uint32(len(req)))
	if _, err := c.conn.Write(append(msg, req...)); err != nil {
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(c.conn, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > maxMessage {
		return nil, errors.New("agent: invalid response length")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c.conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Key is a key held by the agent.
type Key struct {
	Blob    []byte
	Comment string
}

// List returns the agent's keys.
func (c *Client) List() ([]Key, error) {
	resp, err := c.call([]byte{msgRequestIdentities})
	if err != nil {
		return nil, err
	}
	if resp[0] != msgIdentitiesAnswer {
		return nil, fmt.Errorf("agent: unexpected answer %d to the list request", resp[0])
	}
	r := reader{b: resp[1:]}
	n := r.uint32()
	if n > 1024 {
		return nil, errors.New("agent: too many keys")
	}
	var keys []Key
	for i := uint32(0); i < n; i++ {
		blob, comment := r.string(), r.string()
		if r.err != nil {
			return nil, r.err
		}
		keys = append(keys, Key{Blob: blob, Comment: string(comment)})
	}
	return keys, nil
}

// Sign has the agent sign data with the key blob and the signature
// algorithm algo.
func (c *Client) Sign(blob, data []byte, algo string) ([]byte, error) {
	var flags uint32
	switch algo {
	case ssh.SigRSASHA256:
		flags = flagRSASHA256
	case ssh.SigRSASHA512:
		flags = flagRSASHA512
	}
	req := []byte{msgSignRequest}
	req = appendString(req, blob)
	req = appendString(req, data)
	req = binary.BigEndian.AppendUint32(req, flags)
	resp, err := c.call(req)
	if err != nil {
		return nil, err
	}
	switch resp[0] {
	case msgSignResponse:
	case msgFailure:
		return nil, errors.New("agent: the agent refused to sign")
	default:
		return nil, fmt.Errorf("agent: unexpected answer %d to the sign request", resp[0])
	}
	r := reader{b: resp[1:]}
	sig := r.string()
	if r.err != nil {
		return nil, r.err
	}
	got := reader{b: sig}
	if a := string(got.string()); got.err != nil || a != algo {
		return nil, fmt.Errorf("agent: signed with %q instead of %q", a, algo)
	}
	return sig, nil
}

// Signers returns the agent's keys as ssh.Signer; keys that wdyapt does
// not know (such as certificates) are left out.
func (c *Client) Signers() ([]ssh.Signer, error) {
	keys, err := c.List()
	if err != nil {
		return nil, err
	}
	var out []ssh.Signer
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		out = append(out, &signer{c: c, pub: pub})
	}
	return out, nil
}

type signer struct {
	c   *Client
	pub ssh.PublicKey
}

func (s *signer) PublicKey() ssh.PublicKey { return s.pub }

func (s *signer) Sign(data []byte, algo string) ([]byte, error) {
	return s.c.Sign(s.pub.Marshal(), data, algo)
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) uint32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = errors.New("agent: malformed message")
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) string() []byte {
	n := r.uint32()
	if r.err != nil || int(n) > len(r.b) {
		r.err = errors.New("agent: malformed message")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
