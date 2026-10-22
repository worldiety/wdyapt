package ssh

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// AuthMethod is an authentication method (RFC 4252, RFC 4256).
type AuthMethod interface {
	method() string
}

type passwordMethod struct{ password []byte }

func (passwordMethod) method() string { return "password" }

// Password authenticates with a password.
func Password(password []byte) AuthMethod { return passwordMethod{password} }

type keyboardMethod struct{ password []byte }

func (keyboardMethod) method() string { return "keyboard-interactive" }

// KeyboardInteractive answers a single hidden prompt with the password,
// as servers do that check passwords via PAM.
func KeyboardInteractive(password []byte) AuthMethod { return keyboardMethod{password} }

type publicKeyMethod struct {
	source  string
	signers []Signer
}

func (publicKeyMethod) method() string { return "publickey" }

// PublicKeys authenticates with keys; source names their origin in
// messages, such as "identity file" or "ssh-agent".
func PublicKeys(source string, signers ...Signer) AuthMethod {
	return publicKeyMethod{source: source, signers: signers}
}

// AuthError reports a failed authentication: what was tried and what the
// server allows; never credentials.
type AuthError struct {
	User    string
	Tried   []string
	Allowed []string
}

func (e *AuthError) Error() string {
	tried := "nothing (no credentials for the methods the server allows)"
	if len(e.Tried) > 0 {
		tried = strings.Join(e.Tried, ", ")
	}
	return fmt.Sprintf("ssh: login as %q failed; tried %s; the server allows %s", e.User, tried, strings.Join(e.Allowed, ", "))
}

// authenticate logs the client in: first "none" to learn the allowed
// methods, then publickey, password and keyboard-interactive in the
// order of cfg.Auth, each only if the server allows it.
func (c *Client) authenticate(cfg *ClientConfig) error {
	if err := c.c.writePacket(newBuilder(msgServiceRequest).text("ssh-userauth").b); err != nil {
		return err
	}
	p, err := c.readAuth(cfg)
	if err != nil {
		return err
	}
	if p[0] != msgServiceAccept {
		return fmt.Errorf("ssh: the server refused the authentication service (message %d)", p[0])
	}
	req := func(method string) *builder {
		return newBuilder(msgUserauthRequest).text(cfg.User).text("ssh-connection").text(method)
	}
	if err := c.c.writePacket(req("none").b); err != nil {
		return err
	}
	ok, allowed, err := c.authResult(cfg)
	if err != nil || ok {
		if ok {
			c.AuthMethod = "none"
		}
		return err
	}
	var tried []string
	for _, m := range cfg.Auth {
		if !slices.Contains(allowed, m.method()) {
			continue
		}
		var success bool
		var next []string
		switch m := m.(type) {
		case publicKeyMethod:
			for _, s := range m.signers {
				label := fmt.Sprintf("publickey (%s, %s %s)", m.source, s.PublicKey().Type(), Fingerprint(s.PublicKey()))
				tried = append(tried, label)
				success, next, err = c.tryPublicKey(cfg, s)
				if err != nil {
					return err
				}
				if success {
					c.AuthMethod = label
					return nil
				}
				if next != nil {
					allowed = next
				}
				if !slices.Contains(allowed, "publickey") {
					break
				}
			}
			continue
		case passwordMethod:
			tried = append(tried, "password")
			if err := c.c.writePacket(req("password").bool(false).string(m.password).b); err != nil {
				return err
			}
			success, next, err = c.authResult(cfg)
		case keyboardMethod:
			tried = append(tried, "keyboard-interactive")
			success, next, err = c.tryKeyboard(cfg, m.password)
		}
		if err != nil {
			return err
		}
		if success {
			c.AuthMethod = m.method()
			return nil
		}
		if next != nil {
			allowed = next
		}
	}
	return &AuthError{User: cfg.User, Tried: tried, Allowed: allowed}
}

// readAuth reads the next authentication message; banners from the
// server go to cfg.Banner.
func (c *Client) readAuth(cfg *ClientConfig) ([]byte, error) {
	for {
		p, err := c.c.readPacket()
		if err != nil {
			return nil, err
		}
		if p[0] != msgUserauthBanner {
			return p, nil
		}
		r := newParser(p[1:])
		text := r.text()
		if cfg.Banner != nil && r.err == nil {
			cfg.Banner(sanitize(text))
		}
	}
}

// authResult reads SUCCESS or FAILURE along with the methods still allowed.
func (c *Client) authResult(cfg *ClientConfig) (bool, []string, error) {
	p, err := c.readAuth(cfg)
	if err != nil {
		return false, nil, err
	}
	switch p[0] {
	case msgUserauthSuccess:
		return true, nil, nil
	case msgUserauthFailure:
		r := newParser(p[1:])
		methods := r.nameList()
		r.bool()
		if r.err != nil {
			return false, nil, r.err
		}
		return false, methods, nil
	case msgUserauth60:
		return false, nil, errors.New("ssh: the server demands a new password (PASSWD_CHANGEREQ); change it interactively first")
	}
	return false, nil, fmt.Errorf("ssh: unexpected message %d during authentication", p[0])
}

// tryPublicKey first asks without a signature whether the server accepts
// the key, and then signs. RSA signs with rsa-sha2-512 or -256, as
// server-sig-algs names it, never with ssh-rsa.
func (c *Client) tryPublicKey(cfg *ClientConfig, s Signer) (bool, []string, error) {
	pub := s.PublicKey()
	algo := pub.Type()
	if algo == KeyRSA {
		algo = SigRSASHA512
		if v, ok := c.c.ext("server-sig-algs"); ok {
			algos := strings.Split(v, ",")
			switch {
			case slices.Contains(algos, SigRSASHA512):
			case slices.Contains(algos, SigRSASHA256):
				algo = SigRSASHA256
			default:
				return false, nil, nil
			}
		}
	}
	blob := pub.Marshal()
	query := newBuilder(msgUserauthRequest).text(cfg.User).text("ssh-connection").text("publickey").bool(false).text(algo).string(blob)
	if err := c.c.writePacket(query.b); err != nil {
		return false, nil, err
	}
	p, err := c.readAuth(cfg)
	if err != nil {
		return false, nil, err
	}
	switch p[0] {
	case msgUserauthFailure:
		r := newParser(p[1:])
		return false, r.nameList(), r.err
	case msgUserauth60:
	default:
		return false, nil, fmt.Errorf("ssh: unexpected message %d during authentication", p[0])
	}
	data := (&builder{}).string(c.c.t.sessionID).byte(msgUserauthRequest).text(cfg.User).text("ssh-connection").
		text("publickey").bool(true).text(algo).string(blob).b
	sig, err := s.Sign(data, algo)
	if err != nil {
		return false, nil, fmt.Errorf("ssh: signing with %s %s: %w", pub.Type(), Fingerprint(pub), err)
	}
	signed := newBuilder(msgUserauthRequest).text(cfg.User).text("ssh-connection").text("publickey").bool(true).text(algo).string(blob).string(sig)
	if err := c.c.writePacket(signed.b); err != nil {
		return false, nil, err
	}
	return c.authResult(cfg)
}

// tryKeyboard answers INFO_REQUEST: exactly one hidden prompt with the
// password, no prompt with an empty reply; anything else aborts.
func (c *Client) tryKeyboard(cfg *ClientConfig, password []byte) (bool, []string, error) {
	req := newBuilder(msgUserauthRequest).text(cfg.User).text("ssh-connection").text("keyboard-interactive").text("").text("")
	if err := c.c.writePacket(req.b); err != nil {
		return false, nil, err
	}
	answered := false
	for {
		p, err := c.readAuth(cfg)
		if err != nil {
			return false, nil, err
		}
		switch p[0] {
		case msgUserauthSuccess:
			return true, nil, nil
		case msgUserauthFailure:
			r := newParser(p[1:])
			return false, r.nameList(), r.err
		case msgUserauth60:
		default:
			return false, nil, fmt.Errorf("ssh: unexpected message %d during keyboard-interactive", p[0])
		}
		r := newParser(p[1:])
		r.text()
		r.text()
		r.text()
		n := r.uint32()
		if r.err != nil || n > 16 {
			return false, nil, errors.New("ssh: malformed keyboard-interactive request")
		}
		var prompts []string
		var echoes []bool
		for i := uint32(0); i < n; i++ {
			prompts = append(prompts, r.text())
			echoes = append(echoes, r.bool())
		}
		if r.err != nil {
			return false, nil, errors.New("ssh: malformed keyboard-interactive request")
		}
		resp := newBuilder(msgUserauth61).uint32(n)
		switch {
		case n == 0:
		case n == 1 && !echoes[0] && !answered:
			resp.string(password)
			answered = true
		default:
			return false, nil, fmt.Errorf("ssh: keyboard-interactive asks %d questions (%s); wdyapt can only answer one hidden password prompt", n, sanitize(strings.Join(prompts, " | ")))
		}
		if err := c.c.writePacket(resp.b); err != nil {
			return false, nil, err
		}
	}
}
