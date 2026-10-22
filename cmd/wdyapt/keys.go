package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/openpgp"
)

// secretFrom reads a secret from the environment variable variable or from
// the file of the option fileFlag; a line break at the end of the file is
// not part of it. Both at once is wrong usage.
func secretFrom(inv *cli.Invocation, variable, fileFlag string) ([]byte, error) {
	env := inv.Getenv(variable)
	name := inv.String(fileFlag)
	switch {
	case env != "" && name != "":
		return nil, inv.Usagef("set either %s or --%s, not both", variable, fileFlag)
	case env != "":
		return []byte(env), nil
	case name != "":
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(data, "\r\n"), nil
	}
	return nil, nil
}

// readKeyFile reads all keys of a file.
func readKeyFile(name string) ([]*openpgp.Entity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	es, err := openpgp.ReadKeys(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return es, nil
}

// loadSigningKeys reads the signing keys, unlocks them and checks that each
// can sign at time t. If one expires in less than 30 days, it warns.
func loadSigningKeys(inv *cli.Invocation, files []string, passphrase []byte, t time.Time) ([]*openpgp.Entity, error) {
	if len(files) == 0 {
		return nil, inv.Usagef("--signing-key or WDYAPT_SIGNING_KEY is required")
	}
	var out []*openpgp.Entity
	for _, name := range files {
		es, err := readKeyFile(name)
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			if !e.HasSecret() {
				return nil, fmt.Errorf("%s: key %s has no secret part; --signing-key needs the secret key", name, e.Fingerprint())
			}
			if err := e.Unlock(passphrase); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			k, err := e.SigningKey(t)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if !k.Expires.IsZero() && k.Expires.Sub(t) < 30*24*time.Hour {
				inv.Warn("signing key %s expires on %s; create a new key and publish with both keys", k.Public.Fingerprint, k.Expires.Format("2006-01-02"))
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// keyFiles returns the files of a repeatable option.
func keyFiles(inv *cli.Invocation, name string) []string {
	f := inv.Flags.Lookup(name)
	if f == nil {
		return nil
	}
	return f.Value.(*cli.List).Values
}

// loadTrustedKeys reads public keys for the keyring.
func loadTrustedKeys(files []string) ([]*openpgp.Entity, error) {
	var out []*openpgp.Entity
	for _, name := range files {
		es, err := readKeyFile(name)
		if err != nil {
			return nil, err
		}
		out = append(out, es...)
	}
	return out, nil
}

// fingerprints names the fingerprints of keys.
func fingerprints(es []*openpgp.Entity) string {
	var s []string
	for _, e := range es {
		s = append(s, e.Fingerprint().String())
	}
	return strings.Join(s, ", ")
}
