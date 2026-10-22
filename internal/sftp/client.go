// Package sftp is a client for SFTP version 3
// (draft-ietf-secsh-filexfer-02 and OpenSSH's PROTOCOL) over any
// io.ReadWriteCloser, such as an SSH channel; it knows nothing about SSH
// (R-DEC-SSH-AND-SFTP-IN-PROCESS). Reads and writes run with many
// requests in flight at once; it replaces files atomically via
// posix-rename@openssh.com.
package sftp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"sync"
	"time"
)

// Packet types.
const (
	fxpInit          = 1
	fxpVersion       = 2
	fxpOpen          = 3
	fxpClose         = 4
	fxpRead          = 5
	fxpWrite         = 6
	fxpLstat         = 7
	fxpFstat         = 8
	fxpSetstat       = 9
	fxpOpendir       = 11
	fxpReaddir       = 12
	fxpRemove        = 13
	fxpMkdir         = 14
	fxpRealpath      = 16
	fxpStat          = 17
	fxpRename        = 18
	fxpStatus        = 101
	fxpHandle        = 102
	fxpData          = 103
	fxpName          = 104
	fxpAttrs         = 105
	fxpExtended      = 200
	fxpExtendedReply = 201
)

// Flags of OPEN.
const (
	FlagRead   = 0x01
	FlagWrite  = 0x02
	FlagCreate = 0x08
	FlagTrunc  = 0x10
	FlagExcl   = 0x20
)

// Status codes.
const (
	StatusOK            = 0
	StatusEOF           = 1
	StatusNoSuchFile    = 2
	StatusPermission    = 3
	StatusFailure       = 4
	StatusBadMessage    = 5
	StatusOpUnsupported = 8
)

// Attribute flags.
const (
	attrSize        = 0x1
	attrUIDGID      = 0x2
	attrPermissions = 0x4
	attrACModTime   = 0x8
	attrExtended    = 0x80000000
)

// OpenSSH extensions that wdyapt uses.
const (
	ExtPosixRename = "posix-rename@openssh.com"
	ExtFsync       = "fsync@openssh.com"
	ExtLimits      = "limits@openssh.com"
	ExtStatvfs     = "statvfs@openssh.com"
)

const (
	maxPacket   = 1 << 20
	maxInflight = 64
	defaultIO   = 32 << 10
)

// StatusError is a STATUS reply carrying an error.
type StatusError struct {
	Code uint32
	Msg  string
	Op   string
	Path string
}

func (e *StatusError) Error() string {
	msg := e.Msg
	if msg == "" {
		msg = fmt.Sprintf("status %d", e.Code)
	}
	return fmt.Sprintf("sftp %s %s: %s", e.Op, e.Path, msg)
}

// Is maps the codes to the errors of io/fs.
func (e *StatusError) Is(target error) bool {
	switch target {
	case fs.ErrNotExist:
		return e.Code == StatusNoSuchFile
	case fs.ErrPermission:
		return e.Code == StatusPermission
	case errors.ErrUnsupported:
		return e.Code == StatusOpUnsupported
	}
	return false
}

type response struct {
	typ  byte
	data []byte
}

// Client speaks SFTP over rwc.
type Client struct {
	rwc io.ReadWriteCloser
	wmu sync.Mutex

	mu      sync.Mutex
	pending map[uint32]chan response
	nextID  uint32
	err     error

	// Version is the server's protocol version; Extensions its extensions.
	Version    uint32
	Extensions map[string]string

	maxRead, maxWrite int
	// Warn receives notices, such as that the server does not replace
	// atomically.
	Warn func(format string, args ...any)
}

// NewClient negotiates the version (INIT/VERSION) and then reads the
// replies in a goroutine of its own.
func NewClient(rwc io.ReadWriteCloser) (*Client, error) {
	c := &Client{rwc: rwc, pending: map[uint32]chan response{}, Extensions: map[string]string{}, maxRead: defaultIO, maxWrite: defaultIO}
	if _, err := rwc.Write([]byte{0, 0, 0, 5, fxpInit, 0, 0, 0, 3}); err != nil {
		return nil, err
	}
	typ, body, err := readPacket(rwc)
	if err != nil {
		return nil, err
	}
	if typ != fxpVersion {
		return nil, fmt.Errorf("sftp: expected VERSION, got packet %d", typ)
	}
	r := &reader{b: body}
	c.Version = r.uint32()
	for len(r.b) > 0 && r.err == nil {
		name, data := r.string(), r.string()
		c.Extensions[string(name)] = string(data)
	}
	if r.err != nil {
		return nil, errors.New("sftp: malformed VERSION")
	}
	if c.Version < 3 {
		return nil, fmt.Errorf("sftp: the server speaks SFTP version %d; version 3 is needed", c.Version)
	}
	go c.readLoop()
	if _, ok := c.Extensions[ExtLimits]; ok {
		if body, err := c.extended(ExtLimits, nil); err == nil {
			r := &reader{b: body}
			r.uint64()
			read, write := r.uint64(), r.uint64()
			if r.err == nil {
				if read > 0 {
					c.maxRead = int(min(read, 256<<10))
				}
				if write > 0 {
					c.maxWrite = int(min(write, 256<<10))
				}
			}
		}
	}
	return c, nil
}

// readPacket reads a packet: length, type, rest.
func readPacket(r io.Reader) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[:4])
	if n < 1 || n > maxPacket {
		return 0, nil, fmt.Errorf("sftp: invalid packet length %d", n)
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return head[4], body, nil
}

func (c *Client) readLoop() {
	var err error
	for {
		var typ byte
		var body []byte
		typ, body, err = readPacket(c.rwc)
		if err != nil {
			break
		}
		if len(body) < 4 {
			err = errors.New("sftp: packet without request id")
			break
		}
		id := binary.BigEndian.Uint32(body)
		c.mu.Lock()
		ch := c.pending[id]
		delete(c.pending, id)
		c.mu.Unlock()
		if ch == nil {
			err = fmt.Errorf("sftp: answer to unknown request %d", id)
			break
		}
		ch <- response{typ: typ, data: body[4:]}
	}
	if err == io.EOF {
		err = errors.New("sftp: the server closed the connection")
	}
	c.mu.Lock()
	c.err = err
	pending := c.pending
	c.pending = map[uint32]chan response{}
	c.mu.Unlock()
	for _, ch := range pending {
		close(ch)
	}
}

// send sends a request and returns the channel for its reply.
func (c *Client) send(typ byte, payload []byte) (chan response, error) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, c.err
	}
	id := c.nextID
	c.nextID++
	ch := make(chan response, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	msg := make([]byte, 0, 9+len(payload))
	msg = binary.BigEndian.AppendUint32(msg, uint32(5+len(payload)))
	msg = append(msg, typ)
	msg = binary.BigEndian.AppendUint32(msg, id)
	msg = append(msg, payload...)
	c.wmu.Lock()
	_, err := c.rwc.Write(msg)
	c.wmu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

func (c *Client) wait(ch chan response) (response, error) {
	r, ok := <-ch
	if !ok {
		c.mu.Lock()
		defer c.mu.Unlock()
		return response{}, c.err
	}
	return r, nil
}

func (c *Client) call(typ byte, payload []byte) (response, error) {
	ch, err := c.send(typ, payload)
	if err != nil {
		return response{}, err
	}
	return c.wait(ch)
}

// status evaluates a reply that is expected to be STATUS.
func status(r response, op, p string) error {
	if r.typ != fxpStatus {
		return fmt.Errorf("sftp %s %s: unexpected answer %d", op, p, r.typ)
	}
	rd := &reader{b: r.data}
	code, msg := rd.uint32(), string(rd.string())
	if code == StatusOK {
		return nil
	}
	return &StatusError{Code: code, Msg: msg, Op: op, Path: p}
}

// Close ends the session.
func (c *Client) Close() error { return c.rwc.Close() }

// HasExtension reports whether the server offers an extension.
func (c *Client) HasExtension(name string) bool {
	_, ok := c.Extensions[name]
	return ok
}

// Limits gives the size of read and write requests.
func (c *Client) Limits() (read, write int) { return c.maxRead, c.maxWrite }

func (c *Client) extended(name string, payload []byte) ([]byte, error) {
	r, err := c.call(fxpExtended, append(str(name), payload...))
	if err != nil {
		return nil, err
	}
	if r.typ == fxpExtendedReply {
		return r.data, nil
	}
	return nil, status(r, name, "")
}

// FileInfo describes a file on the server.
type FileInfo struct {
	name  string
	size  int64
	mode  fs.FileMode
	mtime time.Time
}

func (f *FileInfo) Name() string       { return f.name }
func (f *FileInfo) Size() int64        { return f.size }
func (f *FileInfo) Mode() fs.FileMode  { return f.mode }
func (f *FileInfo) ModTime() time.Time { return f.mtime }
func (f *FileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f *FileInfo) Sys() any           { return nil }

func (f *FileInfo) Type() fs.FileMode          { return f.mode.Type() }
func (f *FileInfo) Info() (fs.FileInfo, error) { return f, nil }

// readAttrs reads ATTRS.
func readAttrs(r *reader, name string) *FileInfo {
	fi := &FileInfo{name: name}
	flags := r.uint32()
	if flags&attrSize != 0 {
		fi.size = int64(min(r.uint64(), math.MaxInt64))
	}
	if flags&attrUIDGID != 0 {
		r.uint32()
		r.uint32()
	}
	if flags&attrPermissions != 0 {
		fi.mode = posixMode(r.uint32())
	}
	if flags&attrACModTime != 0 {
		r.uint32()
		fi.mtime = time.Unix(int64(r.uint32()), 0)
	}
	if flags&attrExtended != 0 {
		n := r.uint32()
		for i := uint32(0); i < n && r.err == nil; i++ {
			r.string()
			r.string()
		}
	}
	return fi
}

// posixMode translates st_mode into fs.FileMode.
func posixMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & 0o170000 {
	case 0o040000:
		mode |= fs.ModeDir
	case 0o120000:
		mode |= fs.ModeSymlink
	case 0o100000:
	case 0:
	default:
		mode |= fs.ModeIrregular
	}
	return mode
}

func (c *Client) stat(typ byte, p string) (*FileInfo, error) {
	op := map[byte]string{fxpStat: "stat", fxpLstat: "lstat"}[typ]
	r, err := c.call(typ, str(p))
	if err != nil {
		return nil, err
	}
	if r.typ != fxpAttrs {
		return nil, status(r, op, p)
	}
	rd := &reader{b: r.data}
	fi := readAttrs(rd, path.Base(p))
	return fi, rd.err
}

// Stat reads the attributes of p, following symbolic links.
func (c *Client) Stat(p string) (*FileInfo, error) { return c.stat(fxpStat, p) }

// Lstat reads the attributes of p itself.
func (c *Client) Lstat(p string) (*FileInfo, error) { return c.stat(fxpLstat, p) }

// RealPath returns the canonical absolute path.
func (c *Client) RealPath(p string) (string, error) {
	r, err := c.call(fxpRealpath, str(p))
	if err != nil {
		return "", err
	}
	if r.typ != fxpName {
		return "", status(r, "realpath", p)
	}
	rd := &reader{b: r.data}
	if rd.uint32() != 1 {
		return "", errors.New("sftp: realpath returned no single name")
	}
	name := string(rd.string())
	return name, rd.err
}

// ReadDir lists a directory without "." and "..".
func (c *Client) ReadDir(p string) ([]fs.DirEntry, error) {
	h, err := c.handle(fxpOpendir, str(p), "opendir", p)
	if err != nil {
		return nil, err
	}
	defer c.closeHandle(h)
	var out []fs.DirEntry
	for {
		r, err := c.call(fxpReaddir, strBytes(h))
		if err != nil {
			return nil, err
		}
		if r.typ == fxpStatus {
			if err := status(r, "readdir", p); err != nil {
				var se *StatusError
				if errors.As(err, &se) && se.Code == StatusEOF {
					return out, nil
				}
				return nil, err
			}
			return out, nil
		}
		if r.typ != fxpName {
			return nil, fmt.Errorf("sftp readdir %s: unexpected answer %d", p, r.typ)
		}
		rd := &reader{b: r.data}
		n := rd.uint32()
		for i := uint32(0); i < n && rd.err == nil; i++ {
			name := string(rd.string())
			rd.string()
			fi := readAttrs(rd, name)
			if name != "." && name != ".." {
				out = append(out, fi)
			}
		}
		if rd.err != nil {
			return nil, rd.err
		}
	}
}

// Mkdir creates a directory.
func (c *Client) Mkdir(p string) error {
	r, err := c.call(fxpMkdir, append(str(p), attrsPerm(0o755)...))
	if err != nil {
		return err
	}
	return status(r, "mkdir", p)
}

// MkdirAll creates p with all missing parents: STAT, otherwise MKDIR per
// level.
func (c *Client) MkdirAll(p string) error {
	if fi, err := c.Stat(p); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("sftp mkdir %s: exists and is no directory", p)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if parent := path.Dir(p); parent != p && parent != "." && parent != "/" {
		if err := c.MkdirAll(parent); err != nil {
			return err
		}
	}
	if err := c.Mkdir(p); err != nil {
		// Another run may have just created it.
		if fi, serr := c.Stat(p); serr == nil && fi.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

// Remove removes a file.
func (c *Client) Remove(p string) error {
	r, err := c.call(fxpRemove, str(p))
	if err != nil {
		return err
	}
	return status(r, "remove", p)
}

// Rename renames from to to and replaces to atomically, using
// posix-rename@openssh.com. Without the extension: RENAME; if that fails
// because to exists, REMOVE and RENAME with a warning.
func (c *Client) Rename(from, to string) error {
	if c.HasExtension(ExtPosixRename) {
		_, err := c.extended(ExtPosixRename, append(str(from), str(to)...))
		if err != nil {
			if se := (*StatusError)(nil); errors.As(err, &se) {
				se.Op, se.Path = "posix-rename", from
			}
		}
		return err
	}
	r, err := c.call(fxpRename, append(str(from), str(to)...))
	if err != nil {
		return err
	}
	err = status(r, "rename", from)
	if err == nil {
		return nil
	}
	if _, serr := c.Stat(to); serr != nil {
		return err
	}
	if c.Warn != nil {
		c.Warn("the server cannot replace files atomically (no %s); replacing %s by removing it first", ExtPosixRename, to)
	}
	if err := c.Remove(to); err != nil {
		return err
	}
	r, err = c.call(fxpRename, append(str(from), str(to)...))
	if err != nil {
		return err
	}
	return status(r, "rename", from)
}

func (c *Client) handle(typ byte, payload []byte, op, p string) ([]byte, error) {
	r, err := c.call(typ, payload)
	if err != nil {
		return nil, err
	}
	if r.typ != fxpHandle {
		return nil, status(r, op, p)
	}
	rd := &reader{b: r.data}
	h := rd.string()
	if rd.err != nil || len(h) > 256 {
		return nil, fmt.Errorf("sftp %s %s: malformed handle", op, p)
	}
	return h, nil
}

func (c *Client) closeHandle(h []byte) error {
	r, err := c.call(fxpClose, strBytes(h))
	if err != nil {
		return err
	}
	return status(r, "close", "")
}

func attrsPerm(perm uint32) []byte {
	return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, attrPermissions), perm)
}

func str(s string) []byte { return strBytes([]byte(s)) }

func strBytes(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = errors.New("sftp: malformed packet")
	}
}

func (r *reader) uint32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) uint64() uint64 {
	if r.err != nil || len(r.b) < 8 {
		r.fail()
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *reader) string() []byte {
	n := r.uint32()
	if r.err != nil || uint64(n) > uint64(len(r.b)) {
		r.fail()
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
