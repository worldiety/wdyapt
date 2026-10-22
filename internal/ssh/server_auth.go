package ssh

import (
	"errors"
	"fmt"
)

// ServerAuth tells the server whom to let in. It does not offer a method
// without a check function.
type ServerAuth struct {
	Password            func(user string, password []byte) bool
	PublicKey           func(user string, key PublicKey) bool
	KeyboardInteractive bool
	Banner              string
}

// Authenticate performs the authentication on the server side and then
// sets up the channels. It returns the user and the method.
func (s *ServerConn) Authenticate(a ServerAuth) (user, method string, err error) {
	p, err := s.c.readPacket()
	if err != nil {
		return "", "", err
	}
	r := newParser(p[1:])
	if p[0] != msgServiceRequest || r.text() != "ssh-userauth" {
		return "", "", errors.New("ssh: expected the ssh-userauth service request")
	}
	if err := s.c.writePacket(newBuilder(msgServiceAccept).text("ssh-userauth").b); err != nil {
		return "", "", err
	}
	if a.Banner != "" {
		if err := s.c.writePacket(newBuilder(msgUserauthBanner).text(a.Banner).text("").b); err != nil {
			return "", "", err
		}
	}
	var allowed []string
	if a.PublicKey != nil {
		allowed = append(allowed, "publickey")
	}
	if a.Password != nil {
		allowed = append(allowed, "password")
	}
	if a.KeyboardInteractive && a.Password != nil {
		allowed = append(allowed, "keyboard-interactive")
	}
	failure := func() error {
		return s.c.writePacket(newBuilder(msgUserauthFailure).nameList(allowed).bool(false).b)
	}
	for attempt := 0; attempt < 30; attempt++ {
		p, err := s.c.readPacket()
		if err != nil {
			return "", "", err
		}
		if p[0] != msgUserauthRequest {
			return "", "", fmt.Errorf("ssh: unexpected message %d during authentication", p[0])
		}
		r := newParser(p[1:])
		user, service, method := r.text(), r.text(), r.text()
		if r.err != nil || service != "ssh-connection" {
			return "", "", errors.New("ssh: malformed authentication request")
		}
		ok := false
		switch method {
		case "password":
			if a.Password == nil {
				break
			}
			r.bool()
			pw := r.string()
			ok = r.err == nil && a.Password(user, pw)
		case "publickey":
			if a.PublicKey == nil {
				break
			}
			hasSig, algo, blob := r.bool(), r.text(), r.string()
			key, err := ParsePublicKey(blob)
			if err != nil || r.err != nil || keyTypeOf(algo) != key.Type() || algo == KeyRSA || !a.PublicKey(user, key) {
				break
			}
			if !hasSig {
				if err := s.c.writePacket(newBuilder(msgUserauth60).text(algo).string(blob).b); err != nil {
					return "", "", err
				}
				continue
			}
			sig := r.string()
			data := (&builder{}).string(s.SessionID).byte(msgUserauthRequest).text(user).text("ssh-connection").
				text("publickey").bool(true).text(algo).string(blob).b
			if alg, _, err := splitSig(sig); err == nil && alg == algo {
				ok = key.Verify(data, sig) == nil
			}
		case "keyboard-interactive":
			if !a.KeyboardInteractive || a.Password == nil {
				break
			}
			req := newBuilder(msgUserauth60).text("").text("").text("").uint32(1).text("Password: ").bool(false)
			if err := s.c.writePacket(req.b); err != nil {
				return "", "", err
			}
			resp, err := s.c.readPacket()
			if err != nil {
				return "", "", err
			}
			rr := newParser(resp[1:])
			if resp[0] == msgUserauth61 && rr.uint32() == 1 {
				ok = a.Password(user, rr.string()) && rr.err == nil
			}
		}
		if ok {
			if err := s.c.writePacket([]byte{msgUserauthSuccess}); err != nil {
				return "", "", err
			}
			s.mux = newMux(s.c, true, nil)
			return user, method, nil
		}
		if err := failure(); err != nil {
			return "", "", err
		}
	}
	return "", "", errors.New("ssh: too many authentication attempts")
}

// Accept returns the next "session" channel that the client opens.
func (s *ServerConn) Accept() (*Channel, error) {
	if s.mux == nil {
		return nil, errors.New("ssh: not authenticated")
	}
	ch, ok := <-s.mux.incoming
	if !ok {
		return nil, errors.New("ssh: connection closed")
	}
	return ch, nil
}
