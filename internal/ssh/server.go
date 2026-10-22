package ssh

import (
	"errors"
	"io"
)

// ServerConfig controls the server side. wdyapt itself is never a server;
// the test server in sshtest needs the server side of the same building
// blocks.
type ServerConfig struct {
	Config
	HostKeys []Signer
}

// ServerConn is a connection on the server side.
type ServerConn struct {
	c *conn
	// Algorithms names what the first exchange negotiated.
	Algorithms Algorithms
	// SessionID is the hash of the first exchange.
	SessionID []byte
	mux       *mux
}

// NewServerConn performs the version exchange and the first key exchange
// as the server.
func NewServerConn(nc io.ReadWriteCloser, cfg *ServerConfig) (*ServerConn, error) {
	if len(cfg.HostKeys) == 0 {
		return nil, errors.New("ssh: the server has no host key")
	}
	t := newTransport(nc, false, &cfg.Config)
	t.hostKeys = cfg.HostKeys
	if err := t.exchangeVersions(); err != nil {
		return nil, err
	}
	if err := t.kex(nil, nil); err != nil {
		return nil, err
	}
	return &ServerConn{c: newConn(t), Algorithms: t.algos, SessionID: t.sessionID}, nil
}

// ReadPacket returns the next message of a higher layer.
func (s *ServerConn) ReadPacket() ([]byte, error) { return s.c.readPacket() }

// WritePacket writes a message of a higher layer.
func (s *ServerConn) WritePacket(p []byte) error { return s.c.writePacket(p) }

// Close closes the connection.
func (s *ServerConn) Close() error { return s.c.close() }

// Rekeys returns the number of key re-exchanges.
func (s *ServerConn) Rekeys() int { return s.c.rekeys() }
