package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
	"github.com/worldiety/wdyapt/internal/openpgp"
)

// keyCommand is the group "key": OpenPGP keys of the repository.
func keyCommand() *cli.Command {
	return &cli.Command{
		Name:        "key",
		Summary:     "Create, show and export OpenPGP signing keys",
		Description: "Commands for the OpenPGP keys that sign a repository: create a new key, show what a key file contains, and write the public key for apt.",
		Commands:    []*cli.Command{keyGenerateCommand(), keyShowCommand(), keyExportCommand()},
	}
}

func keyGenerateCommand() *cli.Command {
	return &cli.Command{
		Name:    "generate",
		Summary: "Create an OpenPGP signing key for a repository",
		Description: `Creates a new OpenPGP key (version 4, Ed25519) that can sign a repository, and writes three files:

  PREFIX.secret.asc   the secret key, mode 0600, never overwritten
  PREFIX.gpg          the public key for /etc/apt/keyrings (Signed-By)
  PREFIX.asc          the public key as ASCII armor

With a passphrase in WDYAPT_SIGNING_KEY_PASSPHRASE or --passphrase-file the secret key is protected (AES-256, iterated and salted S2K). The fingerprint is printed on standard output.`,
		Flags: func(fs *flag.FlagSet) {
			fs.String("user-id", "", "user ID `TEXT` of the key, e.g. \"Example APT <apt@example.com>\"")
			fs.Duration("expires", 0, "let the key expire after this `DURATION`, e.g. 17520h for two years (default never)")
			fs.String("passphrase-file", "", "protect the secret key with the passphrase in `FILE` (or set WDYAPT_SIGNING_KEY_PASSPHRASE)")
			fs.String("out", "", "`PREFIX` of the files to write, e.g. keys/apt")
			outputFlags(fs, true)
		},
		Env:     map[string]string{"passphrase-file": "WDYAPT_SIGNING_KEY_PASSPHRASE_FILE"},
		Secrets: signingSecrets,
		Run:     runKeyGenerate,
	}
}

func keyShowCommand() *cli.Command {
	return &cli.Command{
		Name:    "show",
		Args:    "FILE...",
		Summary: "Show fingerprint, user IDs and capabilities of OpenPGP keys",
		Description: `Shows for every key in every FILE, binary or ASCII armored, as written by wdyapt or GnuPG: fingerprint, key ID, algorithm and size, creation and expiry, user IDs, subkeys with their capabilities, whether the secret part is present and whether it is protected by a passphrase.

Nothing is unlocked; no passphrase is needed.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Bool("json", false, "write the result as one JSON document to standard output")
		},
		Run: runKeyShow,
	}
}

func keyExportCommand() *cli.Command {
	return &cli.Command{
		Name:        "export",
		Summary:     "Write the public key for apt (Signed-By)",
		Description: `Reads a secret or public OpenPGP key and writes its public part, by default in binary form as apt expects it in /etc/apt/keyrings/*.gpg (Signed-By), or ASCII armored with --format armored.`,
		Flags: func(fs *flag.FlagSet) {
			fs.String("signing-key", "", "key `FILE` to read, secret or public")
			fs.String("format", "binary", "output `FORMAT`: binary or armored")
			fs.String("out", "", "write to `FILE` instead of standard output")
		},
		Env: map[string]string{"signing-key": "WDYAPT_SIGNING_KEY"},
		Run: runKeyExport,
	}
}

// runKeyGenerate generates a signing key and writes it to three files; none
// of them may exist yet.
func runKeyGenerate(_ context.Context, inv *cli.Invocation) error {
	if len(inv.Args) > 0 {
		return inv.Usagef("unexpected argument %q", inv.Args[0])
	}
	userID, prefix := inv.String("user-id"), inv.String("out")
	if userID == "" {
		return inv.Usagef("--user-id is required")
	}
	if prefix == "" {
		return inv.Usagef("--out is required")
	}
	passphrase, err := secretFrom(inv, "WDYAPT_SIGNING_KEY_PASSPHRASE", "passphrase-file")
	if err != nil {
		return err
	}
	expires := inv.Flags.Lookup("expires").Value.(flag.Getter).Get().(time.Duration)
	files := map[string]string{"secret": prefix + ".secret.asc", "binary": prefix + ".gpg", "armored": prefix + ".asc"}
	for _, name := range files {
		if _, err := os.Lstat(name); err == nil {
			return fmt.Errorf("%s exists; wdyapt never overwrites key files", name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	e, err := openpgp.Generate(userID, time.Now(), expires)
	if err != nil {
		return err
	}
	secret, err := openpgp.ExportSecretArmored(e, passphrase)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(prefix); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := writeNew(files["secret"], secret, 0o600); err != nil {
		return err
	}
	if err := writeNew(files["binary"], openpgp.Export(e), 0o644); err != nil {
		return err
	}
	if err := writeNew(files["armored"], openpgp.ExportArmored(e), 0o644); err != nil {
		return err
	}
	protection := "not protected; keep the file secret"
	if len(passphrase) > 0 {
		protection = "protected by the passphrase"
	}
	inv.Say("Wrote the secret key to %s (%s)", files["secret"], protection)
	inv.Say("Wrote the public key to %s for /etc/apt/keyrings and %s", files["binary"], files["armored"])
	if inv.Bool("json") {
		return inv.JSON(map[string]any{"fingerprint": e.Fingerprint().String(), "secret_key": files["secret"], "public_key": files["binary"], "public_key_armored": files["armored"]})
	}
	fmt.Fprintln(inv.Stdout, e.Fingerprint())
	return nil
}

// writeNew writes a new file with mode; an existing one stays.
func writeNew(name string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(name)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// keyView describes a key for key show.
type keyView struct {
	Fingerprint  string    `json:"fingerprint"`
	KeyID        string    `json:"key_id"`
	Algorithm    string    `json:"algorithm"`
	Created      time.Time `json:"created"`
	Expires      string    `json:"expires,omitempty"`
	Capabilities string    `json:"capabilities"`
	Secret       string    `json:"secret"`
	Problem      string    `json:"problem,omitempty"`
}

func viewKey(k *openpgp.Key) keyView {
	v := keyView{
		Fingerprint:  k.Public.Fingerprint.String(),
		KeyID:        fmt.Sprintf("%016X", k.Public.KeyID()),
		Algorithm:    k.Public.AlgoName(),
		Created:      k.Public.Created,
		Capabilities: k.Capabilities(),
		Secret:       "no",
	}
	if !k.Expires.IsZero() {
		v.Expires = k.Expires.UTC().Format(time.RFC3339)
	}
	switch p := k.Private; {
	case p == nil:
	case p.Stub:
		v.Secret = "no (stub without secret part)"
	case p.Protected():
		v.Secret = "yes, protected by a passphrase"
	default:
		v.Secret = "yes, not protected"
	}
	switch {
	case k.Revoked:
		v.Problem = "revoked"
	case !k.Bound:
		v.Problem = k.Problem
	case !k.Expires.IsZero() && time.Now().After(k.Expires):
		v.Problem = "expired"
	}
	return v
}

// runKeyShow shows what key files contain.
func runKeyShow(_ context.Context, inv *cli.Invocation) error {
	if len(inv.Args) == 0 {
		return inv.Usagef("name at least one key FILE")
	}
	type entityView struct {
		File    string    `json:"file"`
		Primary keyView   `json:"primary"`
		UserIDs []string  `json:"user_ids"`
		Subkeys []keyView `json:"subkeys"`
	}
	var all []entityView
	for _, name := range inv.Args {
		es, err := readKeyFile(name)
		if err != nil {
			return err
		}
		for _, e := range es {
			v := entityView{File: name, Primary: viewKey(e.Primary), UserIDs: []string{}, Subkeys: []keyView{}}
			for _, u := range e.UserIDs {
				if u.Valid {
					v.UserIDs = append(v.UserIDs, u.Name)
				}
			}
			for _, k := range e.Subkeys {
				v.Subkeys = append(v.Subkeys, viewKey(k))
			}
			all = append(all, v)
		}
	}
	if inv.Bool("json") {
		return inv.JSON(map[string]any{"keys": all})
	}
	for i, v := range all {
		if i > 0 {
			fmt.Fprintln(inv.Stdout)
		}
		fmt.Fprintf(inv.Stdout, "%s:\n", v.File)
		writeKeyView(inv, "", v.Primary)
		for _, u := range v.UserIDs {
			fmt.Fprintf(inv.Stdout, "  user ID       %s\n", u)
		}
		for _, s := range v.Subkeys {
			fmt.Fprintf(inv.Stdout, "  subkey\n")
			writeKeyView(inv, "  ", s)
		}
	}
	return nil
}

func writeKeyView(inv *cli.Invocation, indent string, v keyView) {
	w := inv.Stdout
	expires := v.Expires
	if expires == "" {
		expires = "never"
	}
	fmt.Fprintf(w, "%s  fingerprint   %s\n", indent, v.Fingerprint)
	fmt.Fprintf(w, "%s  key ID        %s\n", indent, v.KeyID)
	fmt.Fprintf(w, "%s  algorithm     %s\n", indent, v.Algorithm)
	fmt.Fprintf(w, "%s  created       %s\n", indent, v.Created.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "%s  expires       %s\n", indent, expires)
	fmt.Fprintf(w, "%s  capabilities  %s (C certify, S sign, E encrypt, A authenticate)\n", indent, v.Capabilities)
	fmt.Fprintf(w, "%s  secret part   %s\n", indent, v.Secret)
	if v.Problem != "" {
		fmt.Fprintf(w, "%s  problem       %s\n", indent, v.Problem)
	}
}

// runKeyExport writes the public part of a key.
func runKeyExport(_ context.Context, inv *cli.Invocation) error {
	if len(inv.Args) > 0 {
		return inv.Usagef("unexpected argument %q; name the key with --signing-key", inv.Args[0])
	}
	name := inv.String("signing-key")
	if name == "" {
		return inv.Usagef("--signing-key is required")
	}
	es, err := readKeyFile(name)
	if err != nil {
		return err
	}
	var data []byte
	for _, e := range es {
		data = append(data, openpgp.Export(e)...)
	}
	switch inv.String("format") {
	case "binary":
	case "armored":
		data = openpgp.Armor(openpgp.PublicKeyBlock, data)
	default:
		return inv.Usagef("--format must be binary or armored")
	}
	if out := inv.String("out"); out != "" {
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return err
		}
		inv.Say("Wrote the public key %s to %s", fingerprints(es), out)
		return nil
	}
	_, err = inv.Stdout.Write(data)
	return err
}
