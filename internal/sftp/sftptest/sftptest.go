// Package sftptest is an SFTP v3 server for tests only. It serves a
// directory: "/" is its root, the login directory is /home/user.
// It can be configured to omit extensions or to abort an upload
// halfway through.
package sftptest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Home is the login directory, relative to the root.
const Home = "/home/user"

// Options configure the server.
type Options struct {
	// NoPosixRename and NoFsync omit the extensions.
	NoPosixRename bool
	NoFsync       bool
	// FailWriteAfter drops the connection as soon as this many bytes have
	// been written to a file (0 means never).
	FailWriteAfter int64
}

// Server serves sessions on Root.
type Server struct {
	Root string
	Opts Options

	mu      sync.Mutex
	written int64
	Log     []string
}

// New creates Root/home/user and returns the server.
func New(root string, opts Options) (*Server, error) {
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(Home)), 0o755); err != nil {
		return nil, err
	}
	return &Server{Root: root, Opts: opts}, nil
}

// Serve serves one session over rw until it ends.
func (s *Server) Serve(rw io.ReadWriter) error {
	sess := &session{s: s, rw: rw, handles: map[string]*handle{}}
	return sess.run()
}

func (s *Server) log(format string, args ...any) {
	s.mu.Lock()
	s.Log = append(s.Log, fmt.Sprintf(format, args...))
	s.mu.Unlock()
}

// Operations returns the recorded operations.
func (s *Server) Operations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Log...)
}

type handle struct {
	f       *os.File
	dir     []fs.DirEntry
	dirDone bool
	path    string
}

type session struct {
	s       *Server
	rw      io.ReadWriter
	handles map[string]*handle
	next    int
}

var errAbort = errors.New("sftptest: aborted on purpose")

func (ss *session) run() error {
	for {
		var head [5]byte
		if _, err := io.ReadFull(ss.rw, head[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(head[:4])
		if n < 1 || n > 1<<20 {
			return errors.New("sftptest: bad length")
		}
		body := make([]byte, n-1)
		if _, err := io.ReadFull(ss.rw, body); err != nil {
			return err
		}
		if head[4] == 1 {
			exts := map[string]string{"limits@openssh.com": "1", "statvfs@openssh.com": "2"}
			if !ss.s.Opts.NoPosixRename {
				exts["posix-rename@openssh.com"] = "1"
			}
			if !ss.s.Opts.NoFsync {
				exts["fsync@openssh.com"] = "1"
			}
			out := binary.BigEndian.AppendUint32(nil, 3)
			names := make([]string, 0, len(exts))
			for k := range exts {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				out = append(out, str(k)...)
				out = append(out, str(exts[k])...)
			}
			if err := ss.send(2, out); err != nil {
				return err
			}
			continue
		}
		if len(body) < 4 {
			return errors.New("sftptest: no id")
		}
		id := body[:4]
		reply, typ, err := ss.handle(head[4], &rd{b: body[4:]})
		if errors.Is(err, errAbort) {
			return err
		}
		if err != nil {
			typ, reply = 101, statusFor(err)
		}
		if err := ss.send(typ, append(append([]byte(nil), id...), reply...)); err != nil {
			return err
		}
	}
}

func (ss *session) send(typ byte, body []byte) error {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)+1))
	out = append(out, typ)
	_, err := ss.rw.Write(append(out, body...))
	return err
}

// local maps a client path to the file system.
func (ss *session) local(p string) (string, string) {
	if !strings.HasPrefix(p, "/") {
		p = Home + "/" + p
	}
	clean := path.Clean(p)
	return filepath.Join(ss.s.Root, filepath.FromSlash(clean)), clean
}

func ok() []byte { return statusBody(0, "") }

func statusBody(code uint32, msg string) []byte {
	b := binary.BigEndian.AppendUint32(nil, code)
	b = append(b, str(msg)...)
	return append(b, str("")...)
}

func statusFor(err error) []byte {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return statusBody(2, "No such file")
	case errors.Is(err, fs.ErrPermission):
		return statusBody(3, "Permission denied")
	case errors.Is(err, io.EOF):
		return statusBody(1, "EOF")
	}
	return statusBody(4, "Failure")
}

func attrs(fi fs.FileInfo) []byte {
	mode := uint32(fi.Mode().Perm())
	switch {
	case fi.IsDir():
		mode |= 0o040000
	case fi.Mode()&fs.ModeSymlink != 0:
		mode |= 0o120000
	default:
		mode |= 0o100000
	}
	b := binary.BigEndian.AppendUint32(nil, 0x1|0x4|0x8)
	b = binary.BigEndian.AppendUint64(b, uint64(fi.Size()))
	b = binary.BigEndian.AppendUint32(b, mode)
	b = binary.BigEndian.AppendUint32(b, uint32(fi.ModTime().Unix()))
	return binary.BigEndian.AppendUint32(b, uint32(fi.ModTime().Unix()))
}

func (ss *session) newHandle(h *handle) []byte {
	ss.next++
	key := fmt.Sprintf("h%d", ss.next)
	ss.handles[key] = h
	return str(key)
}

func (ss *session) handle(typ byte, r *rd) ([]byte, byte, error) {
	switch typ {
	case 3: // OPEN
		p, pflags := r.str(), r.u32()
		lp, cp := ss.local(p)
		flags := 0
		switch {
		case pflags&0x3 == 0x3:
			flags = os.O_RDWR
		case pflags&0x2 != 0:
			flags = os.O_WRONLY
		}
		if pflags&0x8 != 0 {
			flags |= os.O_CREATE
		}
		if pflags&0x10 != 0 {
			flags |= os.O_TRUNC
		}
		if pflags&0x20 != 0 {
			flags |= os.O_EXCL
		}
		f, err := os.OpenFile(lp, flags, 0o644)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				// Like OpenSSH: an existing target is just FAILURE.
				return statusBody(4, "Failure"), 101, nil
			}
			return nil, 0, err
		}
		ss.s.log("open %s", cp)
		return ss.newHandle(&handle{f: f, path: cp}), 102, nil
	case 4: // CLOSE
		key := r.str()
		h := ss.handles[key]
		if h == nil {
			return nil, 0, errors.New("bad handle")
		}
		delete(ss.handles, key)
		if h.f != nil {
			h.f.Close()
		}
		return ok(), 101, nil
	case 5: // READ
		h := ss.handles[r.str()]
		off, n := r.u64(), r.u32()
		if h == nil || h.f == nil {
			return nil, 0, errors.New("bad handle")
		}
		buf := make([]byte, min(n, 64<<10))
		m, err := h.f.ReadAt(buf, int64(off))
		if m == 0 && err != nil {
			return nil, 0, err
		}
		return str(string(buf[:m])), 103, nil
	case 6: // WRITE
		h := ss.handles[r.str()]
		off, data := r.u64(), r.str()
		if h == nil || h.f == nil {
			return nil, 0, errors.New("bad handle")
		}
		if lim := ss.s.Opts.FailWriteAfter; lim > 0 {
			ss.s.mu.Lock()
			ss.s.written += int64(len(data))
			over := ss.s.written > lim
			ss.s.mu.Unlock()
			if over {
				// Like a dropped connection: half of it is already there.
				h.f.WriteAt([]byte(data[:len(data)/2]), int64(off))
				return nil, 0, errAbort
			}
		}
		if _, err := h.f.WriteAt([]byte(data), int64(off)); err != nil {
			return nil, 0, err
		}
		return ok(), 101, nil
	case 7, 17: // LSTAT, STAT
		lp, _ := ss.local(r.str())
		var fi fs.FileInfo
		var err error
		if typ == 7 {
			fi, err = os.Lstat(lp)
		} else {
			fi, err = os.Stat(lp)
		}
		if err != nil {
			return nil, 0, err
		}
		return attrs(fi), 105, nil
	case 8: // FSTAT
		h := ss.handles[r.str()]
		if h == nil || h.f == nil {
			return nil, 0, errors.New("bad handle")
		}
		fi, err := h.f.Stat()
		if err != nil {
			return nil, 0, err
		}
		return attrs(fi), 105, nil
	case 9: // SETSTAT
		return ok(), 101, nil
	case 11: // OPENDIR
		lp, cp := ss.local(r.str())
		entries, err := os.ReadDir(lp)
		if err != nil {
			return nil, 0, err
		}
		return ss.newHandle(&handle{dir: entries, path: cp}), 102, nil
	case 12: // READDIR
		h := ss.handles[r.str()]
		if h == nil {
			return nil, 0, errors.New("bad handle")
		}
		if h.dirDone {
			return nil, 0, io.EOF
		}
		h.dirDone = true
		out := binary.BigEndian.AppendUint32(nil, uint32(len(h.dir)))
		for _, e := range h.dir {
			fi, err := e.Info()
			if err != nil {
				return nil, 0, err
			}
			out = append(out, str(e.Name())...)
			out = append(out, str(e.Name())...)
			out = append(out, attrs(fi)...)
		}
		return out, 104, nil
	case 13: // REMOVE
		lp, cp := ss.local(r.str())
		if err := os.Remove(lp); err != nil {
			return nil, 0, err
		}
		ss.s.log("remove %s", cp)
		return ok(), 101, nil
	case 14: // MKDIR
		lp, cp := ss.local(r.str())
		if err := os.Mkdir(lp, 0o755); err != nil {
			return nil, 0, err
		}
		ss.s.log("mkdir %s", cp)
		return ok(), 101, nil
	case 16: // REALPATH
		_, cp := ss.local(r.str())
		out := binary.BigEndian.AppendUint32(nil, 1)
		out = append(out, str(cp)...)
		out = append(out, str(cp)...)
		return append(out, 0, 0, 0, 0), 104, nil
	case 18: // RENAME, without replacing, as in SFTP v3
		from, to := r.str(), r.str()
		lf, cf := ss.local(from)
		lt, ct := ss.local(to)
		if _, err := os.Lstat(lt); err == nil {
			return statusBody(4, "Failure"), 101, nil
		}
		if err := os.Rename(lf, lt); err != nil {
			return nil, 0, err
		}
		ss.s.log("rename %s %s", cf, ct)
		return ok(), 101, nil
	case 200: // EXTENDED
		switch name := r.str(); name {
		case "posix-rename@openssh.com":
			if ss.s.Opts.NoPosixRename {
				return statusBody(8, "Unsupported"), 101, nil
			}
			lf, cf := ss.local(r.str())
			lt, ct := ss.local(r.str())
			if err := os.Rename(lf, lt); err != nil {
				return nil, 0, err
			}
			ss.s.log("posix-rename %s %s", cf, ct)
			return ok(), 101, nil
		case "fsync@openssh.com":
			h := ss.handles[r.str()]
			if h == nil || h.f == nil || ss.s.Opts.NoFsync {
				return nil, 0, errors.New("bad handle")
			}
			return ok(), 101, h.f.Sync()
		case "limits@openssh.com":
			out := binary.BigEndian.AppendUint64(nil, 256<<10)
			out = binary.BigEndian.AppendUint64(out, 64<<10)
			out = binary.BigEndian.AppendUint64(out, 64<<10)
			return binary.BigEndian.AppendUint64(out, 64), 201, nil
		default:
			return statusBody(8, "Unsupported"), 101, nil
		}
	}
	return statusBody(8, "Unsupported"), 101, nil
}

func str(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

type rd struct{ b []byte }

func (r *rd) u32() uint32 {
	if len(r.b) < 4 {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *rd) u64() uint64 {
	if len(r.b) < 8 {
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *rd) str() string {
	n := r.u32()
	if int(n) > len(r.b) {
		return ""
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return string(v)
}
