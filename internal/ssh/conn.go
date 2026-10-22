package ssh

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// conn is a connection after the first key exchange: a reader goroutine
// accepts all packets, handles transport messages itself (IGNORE, DEBUG,
// EXT_INFO, GLOBAL_REQUEST, KEXINIT) and queues the rest for the higher
// layers. Writers wait during a re-exchange.
type conn struct {
	t *transport

	mu        sync.Mutex
	cond      *sync.Cond
	kexing    bool
	ourInit   []byte
	queue     [][]byte
	err       error
	closed    bool
	extInfo   map[string]string
	kexNumber int
	// deferred are replies that wait until an exchange we started is
	// finished; until then nothing else may go out.
	deferred [][]byte
}

func newConn(t *transport) *conn {
	c := &conn{t: t, extInfo: map[string]string{}}
	c.cond = sync.NewCond(&c.mu)
	go c.readLoop()
	return c
}

func (c *conn) readLoop() {
	for {
		p, err := c.t.readPacket()
		if err == nil {
			err = c.handle(p)
		}
		if err != nil {
			c.mu.Lock()
			if c.err == nil {
				if err == io.EOF || c.closed {
					err = io.EOF
				}
				c.err = err
			}
			c.kexing = false
			c.cond.Broadcast()
			c.mu.Unlock()
			c.t.conn.Close()
			return
		}
	}
}

func (c *conn) handle(p []byte) error {
	switch p[0] {
	case msgIgnore, msgDebug, msgUnimplemented:
		return nil
	case msgDisconnect:
		return disconnectError(p)
	case msgExtInfo:
		r := newParser(p[1:])
		n := r.uint32()
		for i := uint32(0); i < n && r.err == nil && i < 64; i++ {
			name, value := r.text(), r.text()
			c.mu.Lock()
			c.extInfo[name] = value
			c.mu.Unlock()
		}
		return nil
	case msgGlobalRequest:
		r := newParser(p[1:])
		r.text()
		if !r.bool() {
			return nil
		}
		c.mu.Lock()
		if c.kexing {
			c.deferred = append(c.deferred, []byte{msgRequestFailure})
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		return c.t.writePacket([]byte{msgRequestFailure})
	case msgKexInit:
		c.mu.Lock()
		ours := c.ourInit
		c.kexing = true
		c.mu.Unlock()
		err := c.t.kex(p, ours)
		c.mu.Lock()
		c.kexing, c.ourInit = false, nil
		c.kexNumber++
		deferred := c.deferred
		c.deferred = nil
		c.cond.Broadcast()
		c.mu.Unlock()
		if err != nil {
			return fmt.Errorf("ssh: key re-exchange: %w", err)
		}
		for _, d := range deferred {
			if err := c.t.writePacket(d); err != nil {
				return err
			}
		}
		c.t.cfg.logf("Exchanged new keys (%s)", c.t.algos)
		return nil
	case msgNewKeys, msgKex30, msgKex31:
		return fmt.Errorf("ssh: unexpected key exchange message %d", p[0])
	}
	c.mu.Lock()
	c.queue = append(c.queue, p)
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

// writePacket writes a packet of a higher layer. During an exchange it
// waits; if it is time for new keys, it starts the exchange.
func (c *conn) writePacket(p []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.kexing && c.err == nil {
		c.cond.Wait()
	}
	if c.err != nil {
		return c.err
	}
	if c.t.needsRekey() {
		init := c.t.kexInit()
		c.ourInit, c.kexing = init, true
		if err := c.t.writePacket(init); err != nil {
			return err
		}
		for c.kexing && c.err == nil {
			c.cond.Wait()
		}
		if c.err != nil {
			return c.err
		}
	}
	return c.t.writePacket(p)
}

// readPacket returns the next packet for the higher layers.
func (c *conn) readPacket() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.queue) == 0 && c.err == nil {
		c.cond.Wait()
	}
	if len(c.queue) > 0 {
		p := c.queue[0]
		c.queue[0] = nil
		c.queue = c.queue[1:]
		return p, nil
	}
	return nil, c.err
}

// ext returns a value from EXT_INFO.
func (c *conn) ext(name string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.extInfo[name]
	return v, ok
}

// rekeys returns the number of re-exchanges, for tests.
func (c *conn) rekeys() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kexNumber
}

// close sends DISCONNECT and closes the connection.
func (c *conn) close() error {
	c.mu.Lock()
	already := c.closed
	c.closed = true
	c.mu.Unlock()
	if already {
		return nil
	}
	c.t.writePacket(newBuilder(msgDisconnect).uint32(disconnectByApplication).text("closed by wdyapt").text("").b)
	return c.t.conn.Close()
}

// errClosed reports a closed connection.
var errClosed = errors.New("ssh: connection closed")
