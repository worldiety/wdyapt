package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// HostKeyCallback decides whether the host key key of the server addr
// (host:port) is the expected one. There is no "accept everything".
type HostKeyCallback func(addr string, key PublicKey) error

// ClientConfig controls a connection to a server.
type ClientConfig struct {
	Config
	User string
	// Auth are the authentication methods in the order in which they are
	// tried.
	Auth []AuthMethod
	// HostKey checks the host key; required.
	HostKey HostKeyCallback
	// Banner receives the server's banner during authentication; may be
	// nil.
	Banner func(text string)
	// Stderr receives what the server writes to a channel's error output;
	// may be nil.
	Stderr func(text string)

	// rawTransport is only for tests of the transport: no authentication,
	// no channels.
	rawTransport bool
}

// Client is a connection to a server.
type Client struct {
	c *conn
	// Algorithms names what the first exchange negotiated.
	Algorithms Algorithms
	// HostKey is the server's verified host key.
	HostKey PublicKey
	// AuthMethod names the method with which authentication succeeded.
	AuthMethod string
	mux        *mux
}

// Dial connects to addr (host:port), exchanges keys, checks the host key
// and authenticates (R-ACCESS-LOGIN).
func Dial(ctx context.Context, addr string, cfg *ClientConfig) (*Client, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, err := NewClient(ctx, nc, addr, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

// NewClient runs the protocol over an existing connection.
func NewClient(ctx context.Context, nc io.ReadWriteCloser, addr string, cfg *ClientConfig) (*Client, error) {
	if cfg.HostKey == nil {
		return nil, errors.New("ssh: no host key check configured")
	}
	stop := closeOnCancel(ctx, nc)
	defer stop()
	t, err := handshakeClient(nc, addr, cfg)
	if err != nil {
		return nil, err
	}
	key, _ := ParsePublicKey(t.hostKey)
	c := &Client{c: newConn(t.transport), Algorithms: t.algos, HostKey: key}
	if cfg.rawTransport {
		return c, nil
	}
	if err := c.authenticate(cfg); err != nil {
		c.c.close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	c.mux = newMux(c.c, false, cfg.Stderr)
	return c, nil
}

// clientHandshake is the transport after the first exchange.
type clientHandshake struct {
	*transport
	hostKey []byte
}

func handshakeClient(nc io.ReadWriteCloser, addr string, cfg *ClientConfig) (*clientHandshake, error) {
	t := newTransport(nc, true, &cfg.Config)
	h := &clientHandshake{transport: t}
	t.hostKeyCheck = func(key PublicKey, algo string) error {
		h.hostKey = key.Marshal()
		return cfg.HostKey(addr, key)
	}
	if err := t.exchangeVersions(); err != nil {
		return nil, err
	}
	cfg.logf("Server version %q", sanitize(string(t.remoteVersion)))
	if err := t.kex(nil, nil); err != nil {
		var hk *HostKeyError
		if errors.As(err, &hk) {
			t.writePacket(newBuilder(msgDisconnect).uint32(disconnectHostKeyNotVerify).text("host key not verified").text("").b)
		}
		return nil, err
	}
	return h, nil
}

// HostKeyError reports a host key that is not confirmed.
type HostKeyError struct {
	Addr string
	Key  PublicKey
	Msg  string
}

func (e *HostKeyError) Error() string { return e.Msg }

// closeOnCancel closes nc when ctx ends, as long as stop has not been called.
func closeOnCancel(ctx context.Context, nc io.Closer) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			nc.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// Close closes the connection.
func (c *Client) Close() error { return c.c.close() }

// Rekeys returns the number of key re-exchanges.
func (c *Client) Rekeys() int { return c.c.rekeys() }

// FetchHostKey connects to addr, exchanges keys using only the host key
// algorithms algos and returns the host key, like ssh-keyscan; the
// exchange signature is verified, no authentication takes place.
func FetchHostKey(ctx context.Context, addr string, algos []string, timeout time.Duration) (PublicKey, Algorithms, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, Algorithms{}, err
	}
	defer nc.Close()
	stop := closeOnCancel(ctx, nc)
	defer stop()
	var got PublicKey
	errFound := errors.New("found")
	cfg := &ClientConfig{Config: Config{HostKeyAlgorithms: algos}, HostKey: func(_ string, key PublicKey) error {
		got = key
		return errFound
	}}
	t := newTransport(nc, true, &cfg.Config)
	t.hostKeyCheck = func(key PublicKey, _ string) error { return cfg.HostKey(addr, key) }
	if err := t.exchangeVersions(); err != nil {
		return nil, Algorithms{}, err
	}
	err = t.kex(nil, nil)
	if got == nil {
		if ctx.Err() != nil {
			return nil, Algorithms{}, ctx.Err()
		}
		return nil, Algorithms{}, fmt.Errorf("ssh: %w", err)
	}
	t.writePacket(newBuilder(msgDisconnect).uint32(disconnectByApplication).text("host key fetched").text("").b)
	return got, t.algos, nil
}

// readPacket and writePacket give tests and higher layers access to the
// connection.
func (c *Client) readPacket() ([]byte, error) { return c.c.readPacket() }
func (c *Client) writePacket(p []byte) error  { return c.c.writePacket(p) }

// Subsystem opens a "session" channel and starts the subsystem name in
// it, such as "sftp". The channel is an io.ReadWriteCloser.
func (c *Client) Subsystem(ctx context.Context, name string) (*Channel, error) {
	ch, err := c.mux.open(ctx, "session")
	if err != nil {
		return nil, err
	}
	ok, err := ch.request(ctx, "subsystem", true, encodeString([]byte(name)))
	if err != nil {
		ch.Close()
		return nil, err
	}
	if !ok {
		ch.Close()
		return nil, fmt.Errorf("ssh: the server refused the subsystem %q", name)
	}
	return ch, nil
}
