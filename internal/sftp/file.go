package sftp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// File is an open file on the server.
type File struct {
	c      *Client
	h      []byte
	path   string
	offset int64
}

// Open opens p for reading.
func (c *Client) Open(p string) (*File, error) {
	return c.OpenFile(p, FlagRead, 0)
}

// OpenFile opens p with the flags of OPEN; perm applies on creation.
func (c *Client) OpenFile(p string, flags uint32, perm uint32) (*File, error) {
	payload := binary.BigEndian.AppendUint32(str(p), flags)
	if flags&FlagCreate != 0 {
		payload = append(payload, attrsPerm(perm)...)
	} else {
		payload = binary.BigEndian.AppendUint32(payload, 0)
	}
	h, err := c.handle(fxpOpen, payload, "open", p)
	if err != nil {
		return nil, err
	}
	return &File{c: c, h: h, path: p}, nil
}

// CreateExclusive creates p and fails with fs.ErrExist if p already
// exists. OpenSSH reports an existing target as FAILURE; a STAT afterwards
// tells that apart from other errors.
func (c *Client) CreateExclusive(p string, perm uint32) (*File, error) {
	f, err := c.OpenFile(p, FlagWrite|FlagCreate|FlagExcl, perm)
	if err == nil {
		return f, nil
	}
	if _, serr := c.Lstat(p); serr == nil {
		return nil, fmt.Errorf("sftp create %s: %w", p, fs.ErrExist)
	}
	return nil, err
}

// Close closes the file.
func (f *File) Close() error { return f.c.closeHandle(f.h) }

// Sync commits the file to stable storage on the server if it offers
// fsync@openssh.com; otherwise it does nothing.
func (f *File) Sync() error {
	if !f.c.HasExtension(ExtFsync) {
		return nil
	}
	_, err := f.c.extended(ExtFsync, strBytes(f.h))
	return err
}

// Read reads from the current offset.
func (f *File) Read(p []byte) (int, error) {
	n := min(len(p), f.c.maxRead)
	data, err := f.readAt(f.offset, n)
	f.offset += int64(len(data))
	copy(p, data)
	if err != nil {
		return len(data), err
	}
	return len(data), nil
}

func (f *File) readRequest(off int64, n int) []byte {
	payload := strBytes(f.h)
	payload = binary.BigEndian.AppendUint64(payload, uint64(off))
	return binary.BigEndian.AppendUint32(payload, uint32(n))
}

// readResult evaluates the reply to READ.
func (f *File) readResult(r response) ([]byte, error) {
	switch r.typ {
	case fxpData:
		rd := &reader{b: r.data}
		data := rd.string()
		return data, rd.err
	case fxpStatus:
		err := status(r, "read", f.path)
		var se *StatusError
		if errors.As(err, &se) && se.Code == StatusEOF {
			return nil, io.EOF
		}
		if err == nil {
			return nil, io.EOF
		}
		return nil, err
	}
	return nil, fmt.Errorf("sftp read %s: unexpected answer %d", f.path, r.typ)
}

func (f *File) readAt(off int64, n int) ([]byte, error) {
	r, err := f.c.call(fxpRead, f.readRequest(off, n))
	if err != nil {
		return nil, err
	}
	return f.readResult(r)
}

// WriteTo reads the whole file from the current offset into w, with up to
// 64 requests in flight; io.Copy uses it.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	type req struct {
		off int64
		n   int
		ch  chan response
	}
	var queue []req
	next := f.offset
	eof := false
	var total int64
	issue := func() error {
		for len(queue) < maxInflight && !eof {
			ch, err := f.c.send(fxpRead, f.readRequest(next, f.c.maxRead))
			if err != nil {
				return err
			}
			queue = append(queue, req{off: next, n: f.c.maxRead, ch: ch})
			next += int64(f.c.maxRead)
		}
		return nil
	}
	drain := func() {
		for _, q := range queue {
			f.c.wait(q.ch)
		}
		queue = nil
	}
	for {
		if err := issue(); err != nil {
			drain()
			return total, err
		}
		if len(queue) == 0 {
			f.offset += total
			return total, nil
		}
		q := queue[0]
		queue = queue[1:]
		r, err := f.c.wait(q.ch)
		if err != nil {
			drain()
			return total, err
		}
		data, err := f.readResult(r)
		if err == io.EOF {
			eof = true
			continue
		}
		if err != nil {
			drain()
			return total, err
		}
		if _, err := w.Write(data); err != nil {
			drain()
			return total, err
		}
		total += int64(len(data))
		// A short reply leaves a gap; it is read right away before
		// continuing with the later ones.
		for got := len(data); got < q.n && got > 0; {
			more, err := f.readAt(q.off+int64(got), q.n-got)
			if err == io.EOF {
				eof = true
				break
			}
			if err != nil {
				drain()
				return total, err
			}
			if len(more) == 0 {
				break
			}
			if _, err := w.Write(more); err != nil {
				drain()
				return total, err
			}
			total += int64(len(more))
			got += len(more)
		}
	}
}

// Write writes p at the current offset.
func (f *File) Write(p []byte) (int, error) {
	n, err := f.ReadFrom(&sliceReader{b: p})
	return int(n), err
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

// ReadFrom writes everything from r at the current offset, with up to 64
// requests in flight.
func (f *File) ReadFrom(r io.Reader) (int64, error) {
	var queue []chan response
	var total int64
	var firstErr error
	collect := func(ch chan response) {
		resp, err := f.c.wait(ch)
		if err == nil {
			err = status(resp, "write", f.path)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	buf := make([]byte, f.c.maxWrite)
	for firstErr == nil {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			payload := strBytes(f.h)
			payload = binary.BigEndian.AppendUint64(payload, uint64(f.offset))
			payload = append(payload, strBytes(buf[:n])...)
			ch, err := f.c.send(fxpWrite, payload)
			if err != nil {
				firstErr = err
				break
			}
			queue = append(queue, ch)
			f.offset += int64(n)
			total += int64(n)
			if len(queue) >= maxInflight {
				collect(queue[0])
				queue = queue[1:]
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			firstErr = rerr
		}
	}
	for _, ch := range queue {
		collect(ch)
	}
	return total, firstErr
}
