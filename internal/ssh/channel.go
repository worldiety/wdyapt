package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Window and packet size of our own channels (RFC 4254, 5.2).
const (
	channelWindow    = 2 << 20
	channelMaxPacket = 32 << 10
)

// mux distributes the connection's messages to channels.
type mux struct {
	c      *conn
	server bool
	stderr func(string)

	mu       sync.Mutex
	chans    map[uint32]*Channel
	nextID   uint32
	err      error
	incoming chan *Channel
}

func newMux(c *conn, server bool, stderr func(string)) *mux {
	m := &mux{c: c, server: server, stderr: stderr, chans: map[uint32]*Channel{}, incoming: make(chan *Channel, 16)}
	go m.loop()
	return m
}

func (m *mux) newChannel() *Channel {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := &Channel{m: m, localID: m.nextID, localWindow: channelWindow, opened: make(chan error, 1), replies: make(chan bool, 4), Requests: make(chan *Request, 4)}
	ch.cond = sync.NewCond(&ch.mu)
	m.chans[ch.localID] = ch
	m.nextID++
	return ch
}

func (m *mux) channel(id uint32) *Channel {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.chans[id]
}

func (m *mux) loop() {
	var err error
	for {
		var p []byte
		if p, err = m.c.readPacket(); err != nil {
			break
		}
		if err = m.handle(p); err != nil {
			break
		}
	}
	m.mu.Lock()
	m.err = err
	chans := m.chans
	m.chans = map[uint32]*Channel{}
	m.mu.Unlock()
	for _, ch := range chans {
		ch.fail(err)
	}
	close(m.incoming)
	if !errors.Is(err, io.EOF) {
		m.c.close()
	}
}

func (m *mux) handle(p []byte) error {
	r := newParser(p[1:])
	switch p[0] {
	case msgChannelOpen:
		typ, sender, window, maxPacket := r.text(), r.uint32(), r.uint32(), r.uint32()
		if r.err != nil {
			return r.err
		}
		if !m.server || typ != "session" {
			return m.c.writePacket(newBuilder(msgChannelOpenFailure).uint32(sender).uint32(1).text("channel type not supported").text("").b)
		}
		ch := m.newChannel()
		ch.remoteID, ch.remoteWindow, ch.remoteMax = sender, window, maxPacket
		if err := m.c.writePacket(newBuilder(msgChannelOpenConfirm).uint32(sender).uint32(ch.localID).uint32(channelWindow).uint32(channelMaxPacket).b); err != nil {
			return err
		}
		m.incoming <- ch
		return nil
	case msgGlobalRequest, msgRequestSuccess, msgRequestFailure:
		return nil
	case msgUserauthSuccess, msgUserauthFailure, msgUserauthBanner:
		return nil
	}
	if p[0] < msgChannelOpenConfirm || p[0] > msgChannelFailure {
		return nil
	}
	id := r.uint32()
	if r.err != nil {
		return r.err
	}
	ch := m.channel(id)
	if ch == nil {
		return fmt.Errorf("ssh: message %d for unknown channel %d", p[0], id)
	}
	switch p[0] {
	case msgChannelOpenConfirm:
		ch.mu.Lock()
		ch.remoteID, ch.remoteWindow, ch.remoteMax = r.uint32(), r.uint32(), r.uint32()
		ch.mu.Unlock()
		ch.opened <- r.err
	case msgChannelOpenFailure:
		code, reason := r.uint32(), r.text()
		m.mu.Lock()
		delete(m.chans, id)
		m.mu.Unlock()
		ch.opened <- fmt.Errorf("ssh: the server refused the channel (%d): %s", code, sanitize(reason))
	case msgChannelWindowAdjust:
		n := r.uint32()
		ch.mu.Lock()
		if uint64(ch.remoteWindow)+uint64(n) > 1<<32-1 {
			ch.mu.Unlock()
			return errors.New("ssh: channel window overflow")
		}
		ch.remoteWindow += n
		ch.cond.Broadcast()
		ch.mu.Unlock()
	case msgChannelData:
		return ch.deliver(r.string(), r.err)
	case msgChannelExtendedData:
		r.uint32()
		data := r.string()
		if r.err != nil {
			return r.err
		}
		if m.stderr != nil {
			m.stderr(sanitize(string(data)))
		}
		return ch.consume(len(data))
	case msgChannelEOF:
		ch.mu.Lock()
		ch.eof = true
		ch.cond.Broadcast()
		ch.mu.Unlock()
	case msgChannelClose:
		ch.mu.Lock()
		ch.eof, ch.remoteClosed = true, true
		sent := ch.sentClose
		ch.sentClose = true
		ch.cond.Broadcast()
		ch.mu.Unlock()
		m.mu.Lock()
		delete(m.chans, id)
		m.mu.Unlock()
		ch.end()
		if !sent {
			return m.c.writePacket(newBuilder(msgChannelClose).uint32(ch.remoteID).b)
		}
	case msgChannelRequest:
		typ, want := r.text(), r.bool()
		if r.err != nil {
			return r.err
		}
		req := &Request{Type: typ, WantReply: want, Payload: r.rest(), ch: ch}
		if m.server {
			select {
			case ch.Requests <- req:
				return nil
			default:
			}
		}
		if want {
			return m.c.writePacket(newBuilder(msgChannelFailure).uint32(ch.remoteID).b)
		}
	case msgChannelSuccess, msgChannelFailure:
		select {
		case ch.replies <- p[0] == msgChannelSuccess:
		default:
			return errors.New("ssh: unexpected channel reply")
		}
	}
	return nil
}

// open opens a channel of type typ.
func (m *mux) open(ctx context.Context, typ string) (*Channel, error) {
	ch := m.newChannel()
	if err := m.c.writePacket(newBuilder(msgChannelOpen).text(typ).uint32(ch.localID).uint32(channelWindow).uint32(channelMaxPacket).b); err != nil {
		return nil, err
	}
	select {
	case err := <-ch.opened:
		if err != nil {
			return nil, err
		}
		return ch, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Request is a request to a channel, such as "subsystem".
type Request struct {
	Type      string
	WantReply bool
	Payload   []byte
	ch        *Channel
}

// Reply answers the request if a reply is wanted.
func (r *Request) Reply(ok bool) error {
	if !r.WantReply {
		return nil
	}
	msg := byte(msgChannelFailure)
	if ok {
		msg = msgChannelSuccess
	}
	return r.ch.m.c.writePacket(newBuilder(msg).uint32(r.ch.remoteID).b)
}

// Channel is a channel as in RFC 4254: reading and writing with flow
// control through windows.
type Channel struct {
	m                 *mux
	localID, remoteID uint32
	opened            chan error
	replies           chan bool
	// Requests receives the client's requests on the server side.
	Requests chan *Request

	endOnce sync.Once

	mu                      sync.Mutex
	cond                    *sync.Cond
	buf                     []byte
	eof, remoteClosed       bool
	sentEOF, sentClose      bool
	err                     error
	remoteWindow, remoteMax uint32
	localWindow, consumed   uint32
}

func (ch *Channel) fail(err error) {
	ch.mu.Lock()
	if ch.err == nil {
		ch.err = err
	}
	ch.cond.Broadcast()
	ch.mu.Unlock()
	select {
	case ch.opened <- err:
	default:
	}
	ch.end()
}

// end closes the paths on which the channel delivers replies and
// requests; nothing comes after that.
func (ch *Channel) end() {
	ch.endOnce.Do(func() {
		close(ch.replies)
		close(ch.Requests)
	})
}

// deliver accepts data, at most as much as the window allows.
func (ch *Channel) deliver(data []byte, err error) error {
	if err != nil {
		return err
	}
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if uint32(len(data)) > ch.localWindow {
		return errors.New("ssh: the other side sent more than the channel window allows")
	}
	ch.localWindow -= uint32(len(data))
	ch.buf = append(ch.buf, data...)
	ch.cond.Broadcast()
	return nil
}

// consume accounts for bytes read and refills the window as soon as
// half of it is used up.
func (ch *Channel) consume(n int) error {
	ch.mu.Lock()
	ch.consumed += uint32(n)
	var adjust uint32
	if ch.consumed >= channelWindow/2 {
		adjust, ch.consumed = ch.consumed, 0
		ch.localWindow += adjust
	}
	remote := ch.remoteID
	closed := ch.sentClose
	ch.mu.Unlock()
	if adjust > 0 && !closed {
		return ch.m.c.writePacket(newBuilder(msgChannelWindowAdjust).uint32(remote).uint32(adjust).b)
	}
	return nil
}

// request sends a request and waits for the reply.
func (ch *Channel) request(ctx context.Context, typ string, want bool, payload []byte) (bool, error) {
	if err := ch.m.c.writePacket(newBuilder(msgChannelRequest).uint32(ch.remoteID).text(typ).bool(want).raw(payload).b); err != nil {
		return false, err
	}
	if !want {
		return true, nil
	}
	select {
	case ok, more := <-ch.replies:
		if !more {
			return false, ch.error()
		}
		return ok, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (ch *Channel) error() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.err != nil {
		return ch.err
	}
	return io.EOF
}

// Read reads data from the channel; io.EOF after the peer's EOF.
func (ch *Channel) Read(p []byte) (int, error) {
	ch.mu.Lock()
	for len(ch.buf) == 0 && !ch.eof && ch.err == nil && !ch.sentClose {
		ch.cond.Wait()
	}
	if len(ch.buf) == 0 {
		err := ch.err
		if err == nil || ch.eof {
			err = io.EOF
		}
		ch.mu.Unlock()
		return 0, err
	}
	n := copy(p, ch.buf)
	ch.buf = ch.buf[n:]
	if len(ch.buf) == 0 {
		ch.buf = nil
	}
	ch.mu.Unlock()
	if err := ch.consume(n); err != nil {
		return n, err
	}
	return n, nil
}

// Write writes data in packets that respect the peer's window and packet
// size; if the window is empty, it waits.
func (ch *Channel) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		ch.mu.Lock()
		for ch.remoteWindow == 0 && ch.err == nil && !ch.remoteClosed && !ch.sentClose {
			ch.cond.Wait()
		}
		if ch.err != nil || ch.remoteClosed || ch.sentClose || ch.sentEOF {
			err := ch.err
			if err == nil {
				err = io.ErrClosedPipe
			}
			ch.mu.Unlock()
			return written, err
		}
		n := min(uint32(len(p)), ch.remoteWindow, max(ch.remoteMax, 1), channelMaxPacket)
		ch.remoteWindow -= n
		remote := ch.remoteID
		ch.mu.Unlock()
		if err := ch.m.c.writePacket(newBuilder(msgChannelData).uint32(remote).string(p[:n]).b); err != nil {
			return written, err
		}
		written += int(n)
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends EOF.
func (ch *Channel) CloseWrite() error {
	ch.mu.Lock()
	if ch.sentEOF || ch.sentClose {
		ch.mu.Unlock()
		return nil
	}
	ch.sentEOF = true
	remote := ch.remoteID
	ch.mu.Unlock()
	return ch.m.c.writePacket(newBuilder(msgChannelEOF).uint32(remote).b)
}

// Close closes the channel.
func (ch *Channel) Close() error {
	ch.mu.Lock()
	if ch.sentClose {
		ch.mu.Unlock()
		return nil
	}
	ch.sentClose = true
	remote := ch.remoteID
	ch.cond.Broadcast()
	ch.mu.Unlock()
	return ch.m.c.writePacket(newBuilder(msgChannelClose).uint32(remote).b)
}
