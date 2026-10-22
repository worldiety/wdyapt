package ssh

import (
	"crypto"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

// Key exchange algorithms in the client's order of preference.
var defaultKex = []string{
	"mlkem768x25519-sha256",
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"ecdh-sha2-nistp521",
	"diffie-hellman-group16-sha512",
	"diffie-hellman-group14-sha256",
}

// Host key algorithms in the client's order of preference.
var defaultHostKeyAlgos = []string{KeyEd25519, KeyECDSA256, KeyECDSA384, KeyECDSA521, SigRSASHA512, SigRSASHA256}

// Markers in the first KEXINIT.
const (
	extInfoC       = "ext-info-c"
	extInfoS       = "ext-info-s"
	kexStrictC     = "kex-strict-c-v00@openssh.com"
	kexStrictS     = "kex-strict-s-v00@openssh.com"
	maxKexMessages = 4
)

// kexIO is what an exchange needs from the transport.
type kexIO interface {
	writePacket(p []byte) error
	readPacket() ([]byte, error)
}

// kexMagics are the parts of the exchange hash that are fixed before the
// exchange: both sides' identification strings and both KEXINITs.
type kexMagics struct {
	clientVersion, serverVersion []byte
	clientKexInit, serverKexInit []byte
}

func (m *kexMagics) write(b *builder) {
	b.string(m.clientVersion).string(m.serverVersion).string(m.clientKexInit).string(m.serverKexInit)
}

// kexResult is the result of an exchange: the hash H, the shared secret K
// (already encoded as mpint or string), the host key and its signature
// over H.
type kexResult struct {
	H, K      []byte
	Hash      crypto.Hash
	HostKey   []byte
	Signature []byte
}

type kexAlgorithm interface {
	client(t kexIO, m *kexMagics) (*kexResult, error)
	server(t kexIO, m *kexMagics, host Signer, algo string) (*kexResult, error)
}

func kexByName(name string) kexAlgorithm {
	switch name {
	case "mlkem768x25519-sha256":
		return mlkemKex{}
	case "curve25519-sha256", "curve25519-sha256@libssh.org":
		return ecdhKex{curve: ecdh.X25519(), hash: crypto.SHA256, x25519: true}
	case "ecdh-sha2-nistp256":
		return ecdhKex{curve: ecdh.P256(), hash: crypto.SHA256}
	case "ecdh-sha2-nistp384":
		return ecdhKex{curve: ecdh.P384(), hash: crypto.SHA384}
	case "ecdh-sha2-nistp521":
		return ecdhKex{curve: ecdh.P521(), hash: crypto.SHA512}
	case "diffie-hellman-group14-sha256":
		return dhKex{p: group14, hash: crypto.SHA256}
	case "diffie-hellman-group16-sha512":
		return dhKex{p: group16, hash: crypto.SHA512}
	}
	return nil
}

// readKexReply reads the server's reply: K_S, Q_S or f, signature.
func readKexReply(t kexIO) (hostKey, value, sig []byte, err error) {
	p, err := t.readPacket()
	if err != nil {
		return nil, nil, nil, err
	}
	if p[0] != msgKex31 {
		return nil, nil, nil, fmt.Errorf("ssh: expected the key exchange reply, got message %d", p[0])
	}
	r := newParser(p[1:])
	hostKey, value, sig = r.string(), r.string(), r.string()
	if err := r.done(); err != nil {
		return nil, nil, nil, err
	}
	return hostKey, value, sig, nil
}

func readKexInit(t kexIO) ([]byte, error) {
	p, err := t.readPacket()
	if err != nil {
		return nil, err
	}
	if p[0] != msgKex30 {
		return nil, fmt.Errorf("ssh: expected the key exchange init, got message %d", p[0])
	}
	r := newParser(p[1:])
	v := r.string()
	return v, r.done()
}

// ecdhKex is curve25519-sha256 and ecdh-sha2-nistp* (RFC 5656, RFC 8731).
type ecdhKex struct {
	curve  ecdh.Curve
	hash   crypto.Hash
	x25519 bool
}

func (k ecdhKex) shared(priv *ecdh.PrivateKey, peer []byte) ([]byte, error) {
	pub, err := k.curve.NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("ssh: invalid key exchange value: %w", err)
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh: key exchange: %w", err)
	}
	if k.x25519 && subtle.ConstantTimeCompare(secret, make([]byte, len(secret))) == 1 {
		return nil, errors.New("ssh: key exchange produced zero")
	}
	return encodeMpint(secret), nil
}

func (k ecdhKex) client(t kexIO, m *kexMagics) (*kexResult, error) {
	priv, err := k.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	qc := priv.PublicKey().Bytes()
	if err := t.writePacket(newBuilder(msgKex30).string(qc).b); err != nil {
		return nil, err
	}
	hostKey, qs, sig, err := readKexReply(t)
	if err != nil {
		return nil, err
	}
	K, err := k.shared(priv, qs)
	if err != nil {
		return nil, err
	}
	b := &builder{}
	m.write(b)
	b.string(hostKey).string(qc).string(qs).raw(K)
	return &kexResult{H: digest(k.hash, b.b), K: K, Hash: k.hash, HostKey: hostKey, Signature: sig}, nil
}

func (k ecdhKex) server(t kexIO, m *kexMagics, host Signer, algo string) (*kexResult, error) {
	qc, err := readKexInit(t)
	if err != nil {
		return nil, err
	}
	priv, err := k.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	qs := priv.PublicKey().Bytes()
	K, err := k.shared(priv, qc)
	if err != nil {
		return nil, err
	}
	hostKey := host.PublicKey().Marshal()
	b := &builder{}
	m.write(b)
	b.string(hostKey).string(qc).string(qs).raw(K)
	H := digest(k.hash, b.b)
	sig, err := host.Sign(H, algo)
	if err != nil {
		return nil, err
	}
	if err := t.writePacket(newBuilder(msgKex31).string(hostKey).string(qs).string(sig).b); err != nil {
		return nil, err
	}
	return &kexResult{H: H, K: K, Hash: k.hash, HostKey: hostKey, Signature: sig}, nil
}

// mlkemKex is mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex):
// ML-KEM-768 and X25519 combined; K is SHA-256 of both secrets and enters
// the hash and key derivation as a string, not as an mpint.
type mlkemKex struct{}

func (mlkemKex) client(t kexIO, m *kexMagics) (*kexResult, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cInit := append(dk.EncapsulationKey().Bytes(), x.PublicKey().Bytes()...)
	if err := t.writePacket(newBuilder(msgKex30).string(cInit).b); err != nil {
		return nil, err
	}
	hostKey, sReply, sig, err := readKexReply(t)
	if err != nil {
		return nil, err
	}
	if len(sReply) != mlkem.CiphertextSize768+32 {
		return nil, errors.New("ssh: invalid mlkem768x25519 reply")
	}
	kemSecret, err := dk.Decapsulate(sReply[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(sReply[mlkem.CiphertextSize768:])
	if err != nil {
		return nil, err
	}
	xSecret, err := x.ECDH(peer)
	if err != nil {
		return nil, err
	}
	K := hybridSecret(kemSecret, xSecret)
	b := &builder{}
	m.write(b)
	b.string(hostKey).string(cInit).string(sReply).raw(K)
	return &kexResult{H: digest(crypto.SHA256, b.b), K: K, Hash: crypto.SHA256, HostKey: hostKey, Signature: sig}, nil
}

func (mlkemKex) server(t kexIO, m *kexMagics, host Signer, algo string) (*kexResult, error) {
	cInit, err := readKexInit(t)
	if err != nil {
		return nil, err
	}
	if len(cInit) != mlkem.EncapsulationKeySize768+32 {
		return nil, errors.New("ssh: invalid mlkem768x25519 init")
	}
	ek, err := mlkem.NewEncapsulationKey768(cInit[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, err
	}
	kemSecret, ct := ek.Encapsulate()
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(cInit[mlkem.EncapsulationKeySize768:])
	if err != nil {
		return nil, err
	}
	xSecret, err := x.ECDH(peer)
	if err != nil {
		return nil, err
	}
	sReply := append(ct, x.PublicKey().Bytes()...)
	K := hybridSecret(kemSecret, xSecret)
	hostKey := host.PublicKey().Marshal()
	b := &builder{}
	m.write(b)
	b.string(hostKey).string(cInit).string(sReply).raw(K)
	H := digest(crypto.SHA256, b.b)
	sig, err := host.Sign(H, algo)
	if err != nil {
		return nil, err
	}
	if err := t.writePacket(newBuilder(msgKex31).string(hostKey).string(sReply).string(sig).b); err != nil {
		return nil, err
	}
	return &kexResult{H: H, K: K, Hash: crypto.SHA256, HostKey: hostKey, Signature: sig}, nil
}

func hybridSecret(kem, x []byte) []byte {
	h := sha256.New()
	h.Write(kem)
	h.Write(x)
	return encodeString(h.Sum(nil))
}

// dhKex is diffie-hellman-group14-sha256 and -group16-sha512 (RFC 8268)
// with the groups from RFC 3526 and g = 2.
type dhKex struct {
	p    *big.Int
	hash crypto.Hash
}

var (
	group14 = mustPrime(`FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF`)
	group16 = mustPrime(`FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF`)
	two     = big.NewInt(2)
)

func mustPrime(hex string) *big.Int {
	p, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("ssh: bad prime")
	}
	return p
}

func (k dhKex) secret() (*big.Int, *big.Int, error) {
	// An exponent twice the length of the hash is enough for the
	// security of the group (RFC 8268, 4).
	max := new(big.Int).Lsh(big.NewInt(1), uint(k.hash.Size()*16))
	x, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, err
	}
	x.Add(x, two)
	return x, new(big.Int).Exp(two, x, k.p), nil
}

func (k dhKex) check(v *big.Int) error {
	pm1 := new(big.Int).Sub(k.p, big.NewInt(1))
	if v.Cmp(big.NewInt(1)) <= 0 || v.Cmp(pm1) >= 0 {
		return errors.New("ssh: Diffie-Hellman value out of range")
	}
	return nil
}

func (k dhKex) client(t kexIO, m *kexMagics) (*kexResult, error) {
	x, e, err := k.secret()
	if err != nil {
		return nil, err
	}
	if err := t.writePacket(newBuilder(msgKex30).mpint(e).b); err != nil {
		return nil, err
	}
	p, err := t.readPacket()
	if err != nil {
		return nil, err
	}
	if p[0] != msgKex31 {
		return nil, fmt.Errorf("ssh: expected the key exchange reply, got message %d", p[0])
	}
	r := newParser(p[1:])
	hostKey, f, sig := r.string(), r.mpint(), r.string()
	if err := r.done(); err != nil {
		return nil, err
	}
	if err := k.check(f); err != nil {
		return nil, err
	}
	K := (&builder{}).mpint(new(big.Int).Exp(f, x, k.p)).b
	b := &builder{}
	m.write(b)
	b.string(hostKey).mpint(e).mpint(f).raw(K)
	return &kexResult{H: digest(k.hash, b.b), K: K, Hash: k.hash, HostKey: hostKey, Signature: sig}, nil
}

func (k dhKex) server(t kexIO, m *kexMagics, host Signer, algo string) (*kexResult, error) {
	p, err := t.readPacket()
	if err != nil {
		return nil, err
	}
	if p[0] != msgKex30 {
		return nil, fmt.Errorf("ssh: expected the key exchange init, got message %d", p[0])
	}
	r := newParser(p[1:])
	e := r.mpint()
	if err := r.done(); err != nil {
		return nil, err
	}
	if err := k.check(e); err != nil {
		return nil, err
	}
	y, f, err := k.secret()
	if err != nil {
		return nil, err
	}
	K := (&builder{}).mpint(new(big.Int).Exp(e, y, k.p)).b
	hostKey := host.PublicKey().Marshal()
	b := &builder{}
	m.write(b)
	b.string(hostKey).mpint(e).mpint(f).raw(K)
	H := digest(k.hash, b.b)
	sig, err := host.Sign(H, algo)
	if err != nil {
		return nil, err
	}
	if err := t.writePacket(newBuilder(msgKex31).string(hostKey).mpint(f).string(sig).b); err != nil {
		return nil, err
	}
	return &kexResult{H: H, K: K, Hash: k.hash, HostKey: hostKey, Signature: sig}, nil
}
