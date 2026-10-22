package ssh

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds the settings that client and server share. Empty lists
// take the defaults.
type Config struct {
	KexAlgorithms     []string
	Ciphers           []string
	MACs              []string
	HostKeyAlgorithms []string
	// RekeyBytes and RekeyInterval trigger a new key exchange; the defaults
	// are 1 GiB per direction and one hour.
	RekeyBytes    uint64
	RekeyInterval time.Duration
	// Version goes into the identification "SSH-2.0-<Version>".
	Version string
	// Logf receives details for --verbose; may be nil.
	Logf func(format string, args ...any)

	// injectBeforeNewKeys is only for tests: the server sends this
	// packet in the first exchange before NEWKEYS (Terrapin).
	injectBeforeNewKeys []byte
}

func (c *Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func orDefault(v, d []string) []string {
	if len(v) == 0 {
		return d
	}
	return v
}

// Algorithms names what an exchange negotiated.
type Algorithms struct {
	Kex, HostKey                           string
	CipherClientServer, CipherServerClient string
	MACClientServer, MACServerClient       string
	StrictKex                              bool
}

func (a Algorithms) String() string {
	mac := func(cipher, m string) string {
		if cipherSpecs[cipher].aead {
			return cipher
		}
		return cipher + " " + m
	}
	s := fmt.Sprintf("kex %s, host key %s, cipher %s", a.Kex, a.HostKey, mac(a.CipherClientServer, a.MACClientServer))
	if a.StrictKex {
		s += ", strict kex"
	}
	return s
}

// transport reads and writes the binary packets of a connection and
// performs the key exchange.
type transport struct {
	conn     io.ReadWriteCloser
	r        *bufio.Reader
	isClient bool
	cfg      *Config

	localVersion, remoteVersion []byte
	sessionID                   []byte
	firstKexDone                bool
	strict                      bool
	algos                       Algorithms

	// hostKeyCheck checks the host key on the client after the signature.
	hostKeyCheck func(key PublicKey, algo string) error
	// hostKeys are the server's keys.
	hostKeys []Signer
	// clientExtInfo records whether the client named ext-info-c.
	clientExtInfo bool

	writeMu     sync.Mutex
	writeCipher packetCipher
	writeSeq    uint32
	written     atomic.Uint64

	readCipher packetCipher
	readSeq    uint32
	read       atomic.Uint64
	lastKex    atomic.Int64
}

func newTransport(conn io.ReadWriteCloser, isClient bool, cfg *Config) *transport {
	if cfg.Version == "" {
		cfg.Version = "wdyapt"
	}
	return &transport{conn: conn, r: bufio.NewReaderSize(conn, 64<<10), isClient: isClient, cfg: cfg, writeCipher: noneCipher{}, readCipher: noneCipher{}}
}

// exchangeVersions sends our own identification and reads the peer's:
// at most 32 lines before "SSH-", each at most 255 bytes, only SSH-2.0 or
// SSH-1.99.
func (t *transport) exchangeVersions() error {
	t.localVersion = []byte("SSH-2.0-" + strings.ReplaceAll(t.cfg.Version, " ", "_"))
	if _, err := t.conn.Write(append(bytes.Clone(t.localVersion), '\r', '\n')); err != nil {
		return err
	}
	for i := 0; i < 32; i++ {
		line, err := t.readLine()
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(line, []byte("SSH-")) {
			continue
		}
		if !bytes.HasPrefix(line, []byte("SSH-2.0-")) && !bytes.HasPrefix(line, []byte("SSH-1.99-")) {
			return fmt.Errorf("ssh: the server speaks %q, not SSH 2", line)
		}
		t.remoteVersion = line
		return nil
	}
	return errors.New("ssh: no SSH version line from the other side")
}

func (t *transport) readLine() ([]byte, error) {
	var line []byte
	for len(line) <= 255 {
		b, err := t.r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return nil, errors.New("ssh: connection closed during the version exchange")
			}
			return nil, err
		}
		if b == '\n' {
			return bytes.TrimSuffix(line, []byte{'\r'}), nil
		}
		line = append(line, b)
	}
	return nil, errors.New("ssh: version line longer than 255 bytes")
}

// writePacket writes a packet; sequence numbers wrap modulo 2^32.
func (t *transport) writePacket(payload []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	err := t.writeCipher.writePacket(t.writeSeq, t.conn, payload)
	t.writeSeq++
	t.written.Add(uint64(len(payload)))
	return err
}

func (t *transport) readPacket() ([]byte, error) {
	p, err := t.readCipher.readPacket(t.readSeq, t.r)
	if err != nil {
		return nil, err
	}
	t.readSeq++
	t.read.Add(uint64(len(p)))
	if len(p) == 0 {
		return nil, errors.New("ssh: empty packet")
	}
	return p, nil
}

// kexInit builds our own KEXINIT.
func (t *transport) kexInit() []byte {
	kex := slices.Clone(orDefault(t.cfg.KexAlgorithms, defaultKex))
	if !t.firstKexDone {
		if t.isClient {
			kex = append(kex, extInfoC, kexStrictC)
		} else {
			kex = append(kex, extInfoS, kexStrictS)
		}
	}
	var hostAlgos []string
	if t.isClient {
		hostAlgos = orDefault(t.cfg.HostKeyAlgorithms, defaultHostKeyAlgos)
	} else {
		for _, k := range t.hostKeys {
			for _, a := range sigAlgos(k.PublicKey().Type()) {
				if len(t.cfg.HostKeyAlgorithms) == 0 || slices.Contains(t.cfg.HostKeyAlgorithms, a) {
					hostAlgos = append(hostAlgos, a)
				}
			}
		}
	}
	ciphers := orDefault(t.cfg.Ciphers, defaultCiphers)
	macs := orDefault(t.cfg.MACs, defaultMACs)
	cookie := make([]byte, 16)
	rand.Read(cookie)
	b := newBuilder(msgKexInit).raw(cookie).nameList(kex).nameList(hostAlgos).
		nameList(ciphers).nameList(ciphers).nameList(macs).nameList(macs).
		nameList([]string{"none"}).nameList([]string{"none"}).nameList(nil).nameList(nil).
		bool(false).uint32(0)
	return b.b
}

type kexInitMsg struct {
	kex, hostKey, cipherCS, cipherSC, macCS, macSC, compCS, compSC []string
	follows                                                        bool
}

func parseKexInit(p []byte) (*kexInitMsg, error) {
	r := newParser(p[1:])
	r.bytes(16)
	m := &kexInitMsg{
		kex: r.nameList(), hostKey: r.nameList(), cipherCS: r.nameList(), cipherSC: r.nameList(),
		macCS: r.nameList(), macSC: r.nameList(), compCS: r.nameList(), compSC: r.nameList(),
	}
	r.nameList()
	r.nameList()
	m.follows = r.bool()
	r.uint32()
	if r.err != nil {
		return nil, errors.New("ssh: malformed KEXINIT")
	}
	return m, nil
}

// choose takes the client's first algorithm that the server knows.
func choose(what string, client, server []string) (string, error) {
	for _, c := range client {
		if slices.Contains(server, c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("ssh: no common %s; we offer %s, the other side %s", what, strings.Join(client, ","), strings.Join(server, ","))
}

// kex performs a key exchange. peerInit is the peer's KEXINIT if it has
// already been read; ourInit our own if it has already been sent.
func (t *transport) kex(peerInit, ourInit []byte) error {
	first := !t.firstKexDone
	if ourInit == nil {
		ourInit = t.kexInit()
		if err := t.writePacket(ourInit); err != nil {
			return err
		}
	}
	if peerInit == nil {
		for {
			p, err := t.readPacket()
			if err != nil {
				return err
			}
			if p[0] == msgKexInit {
				peerInit = p
				break
			}
			// Strict kex requires KEXINIT as the first packet; without it,
			// IGNORE and DEBUG may come before.
			if first || (p[0] != msgIgnore && p[0] != msgDebug) {
				return fmt.Errorf("ssh: expected KEXINIT, got message %d", p[0])
			}
		}
	}
	ours, err := parseKexInit(ourInit)
	if err != nil {
		return err
	}
	peer, err := parseKexInit(peerInit)
	if err != nil {
		return err
	}
	client, server := ours, peer
	magics := &kexMagics{clientKexInit: ourInit, serverKexInit: peerInit, clientVersion: t.localVersion, serverVersion: t.remoteVersion}
	if !t.isClient {
		client, server = peer, ours
		magics = &kexMagics{clientKexInit: peerInit, serverKexInit: ourInit, clientVersion: t.remoteVersion, serverVersion: t.localVersion}
	}
	if first {
		if t.isClient {
			t.strict = slices.Contains(peer.kex, kexStrictS)
		} else {
			t.strict = slices.Contains(peer.kex, kexStrictC)
			t.clientExtInfo = slices.Contains(peer.kex, extInfoC)
		}
	}
	var a Algorithms
	a.StrictKex = t.strict
	strip := func(l []string) []string {
		return slices.DeleteFunc(slices.Clone(l), func(s string) bool {
			return s == extInfoC || s == extInfoS || s == kexStrictC || s == kexStrictS
		})
	}
	if a.Kex, err = choose("key exchange algorithm", strip(client.kex), strip(server.kex)); err != nil {
		return err
	}
	if a.HostKey, err = choose("host key algorithm", client.hostKey, server.hostKey); err != nil {
		return err
	}
	if a.CipherClientServer, err = choose("cipher", client.cipherCS, server.cipherCS); err != nil {
		return err
	}
	if a.CipherServerClient, err = choose("cipher", client.cipherSC, server.cipherSC); err != nil {
		return err
	}
	if !cipherSpecs[a.CipherClientServer].aead {
		if a.MACClientServer, err = choose("MAC", client.macCS, server.macCS); err != nil {
			return err
		}
	}
	if !cipherSpecs[a.CipherServerClient].aead {
		if a.MACServerClient, err = choose("MAC", client.macSC, server.macSC); err != nil {
			return err
		}
	}
	if _, err = choose("compression", client.compCS, server.compCS); err != nil {
		return err
	}
	if _, err = choose("compression", client.compSC, server.compSC); err != nil {
		return err
	}
	algo := kexByName(a.Kex)
	if algo == nil || keyTypeOf(a.HostKey) == "" {
		return fmt.Errorf("ssh: unsupported key exchange %s", a.Kex)
	}
	t.cfg.logf("Negotiated %s", a)

	// If the peer guessed wrong, we discard its next packet.
	if peer.follows && (peer.kex[0] != a.Kex || peer.hostKey[0] != a.HostKey) {
		if _, err := t.readPacket(); err != nil {
			return err
		}
	}

	kio := &kexReader{t: t, strict: first && t.strict}
	var res *kexResult
	if t.isClient {
		res, err = algo.client(kio, magics)
		if err != nil {
			return err
		}
		key, err := ParsePublicKey(res.HostKey)
		if err != nil {
			return err
		}
		if key.Type() != keyTypeOf(a.HostKey) {
			return fmt.Errorf("ssh: the server sent a %s key for %s", key.Type(), a.HostKey)
		}
		sigAlgo, _, err := splitSig(res.Signature)
		if err != nil {
			return err
		}
		if sigAlgo != a.HostKey {
			return fmt.Errorf("ssh: the server signed with %s instead of %s", sigAlgo, a.HostKey)
		}
		if err := key.Verify(res.H, res.Signature); err != nil {
			return fmt.Errorf("ssh: the server's signature of the key exchange is invalid: %w", err)
		}
		if t.hostKeyCheck != nil {
			if err := t.hostKeyCheck(key, a.HostKey); err != nil {
				return err
			}
		}
	} else {
		var host Signer
		for _, k := range t.hostKeys {
			if k.PublicKey().Type() == keyTypeOf(a.HostKey) {
				host = k
			}
		}
		if res, err = algo.server(kio, magics, host, a.HostKey); err != nil {
			return err
		}
	}
	if t.sessionID == nil {
		t.sessionID = res.H
	}
	t.algos = a

	// Derive the keys (RFC 4253, 7.2).
	derive := func(letter byte, n int) []byte {
		var out []byte
		h := res.Hash.New()
		h.Write(res.K)
		h.Write(res.H)
		h.Write([]byte{letter})
		h.Write(t.sessionID)
		out = h.Sum(nil)
		for len(out) < n {
			h := res.Hash.New()
			h.Write(res.K)
			h.Write(res.H)
			h.Write(out)
			out = h.Sum(out)
		}
		return out[:n]
	}
	build := func(cipherName, macName string, ivL, keyL, macL byte) (packetCipher, error) {
		spec := cipherSpecs[cipherName]
		var macKey []byte
		if !spec.aead {
			macKey = derive(macL, macSpecs[macName].keyLen)
		}
		return newPacketCipher(cipherName, macName, derive(keyL, spec.keyLen), derive(ivL, spec.ivLen), macKey)
	}
	csCipher, err := build(a.CipherClientServer, a.MACClientServer, 'A', 'C', 'E')
	if err != nil {
		return err
	}
	scCipher, err := build(a.CipherServerClient, a.MACServerClient, 'B', 'D', 'F')
	if err != nil {
		return err
	}
	outCipher, inCipher := csCipher, scCipher
	if !t.isClient {
		outCipher, inCipher = scCipher, csCipher
	}

	if !t.isClient && first && t.cfg.injectBeforeNewKeys != nil {
		if err := t.writePacket(t.cfg.injectBeforeNewKeys); err != nil {
			return err
		}
	}
	// Send NEWKEYS and take the new cipher for our own direction.
	t.writeMu.Lock()
	err = t.writeCipher.writePacket(t.writeSeq, t.conn, []byte{msgNewKeys})
	t.writeSeq++
	t.writeCipher = outCipher
	if t.strict {
		t.writeSeq = 0
	}
	t.written.Store(0)
	t.writeMu.Unlock()
	if err != nil {
		return err
	}
	// Read NEWKEYS.
	for {
		p, err := t.readPacket()
		if err != nil {
			return err
		}
		if p[0] == msgNewKeys {
			break
		}
		if t.strict && first || (p[0] != msgIgnore && p[0] != msgDebug) {
			return fmt.Errorf("ssh: expected NEWKEYS, got message %d", p[0])
		}
	}
	t.readCipher = inCipher
	if t.strict {
		t.readSeq = 0
	}
	t.read.Store(0)
	t.lastKex.Store(time.Now().UnixNano())
	t.firstKexDone = true
	if !t.isClient && first && t.clientExtInfo {
		sigs := []string{KeyEd25519, KeyECDSA256, KeyECDSA384, KeyECDSA521, SigRSASHA512, SigRSASHA256}
		ext := newBuilder(msgExtInfo).uint32(1).text("server-sig-algs").nameList(sigs).b
		if err := t.writePacket(ext); err != nil {
			return err
		}
	}
	return nil
}

// kexReader gives an exchange only its own packets; it skips IGNORE and
// DEBUG, except in the first exchange with strict kex.
type kexReader struct {
	t      *transport
	strict bool
}

func (k *kexReader) writePacket(p []byte) error { return k.t.writePacket(p) }

func (k *kexReader) readPacket() ([]byte, error) {
	for {
		p, err := k.t.readPacket()
		if err != nil {
			return nil, err
		}
		switch p[0] {
		case msgKex30, msgKex31:
			return p, nil
		case msgIgnore, msgDebug:
			if !k.strict {
				continue
			}
		case msgDisconnect:
			return nil, disconnectError(p)
		}
		return nil, fmt.Errorf("ssh: unexpected message %d during the key exchange", p[0])
	}
}

// disconnectError reads the reason of a DISCONNECT.
func disconnectError(p []byte) error {
	r := newParser(p[1:])
	code := r.uint32()
	reason := r.text()
	if r.err != nil {
		return errors.New("ssh: the other side disconnected")
	}
	return fmt.Errorf("ssh: the other side disconnected (%d): %s", code, sanitize(reason))
}

// sanitize removes control characters from text sent by the server before
// it appears in a message.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// needsRekey reports whether it is time for a new exchange.
func (t *transport) needsRekey() bool {
	limit := t.cfg.RekeyBytes
	if limit == 0 {
		limit = 1 << 30
	}
	interval := t.cfg.RekeyInterval
	if interval == 0 {
		interval = time.Hour
	}
	return t.written.Load() >= limit || t.read.Load() >= limit || time.Since(time.Unix(0, t.lastKex.Load())) >= interval
}
