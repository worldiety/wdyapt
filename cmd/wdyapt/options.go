package main

import (
	"flag"
	"maps"
	"time"

	"github.com/worldiety/wdyapt/internal/cli"
)

// Options shared by several commands: access to the storage and the keys
// for signing and verifying.

// remoteFlag registers --remote; readOnly also allows https://.
func remoteFlag(fs *flag.FlagSet, readOnly bool) {
	usage := "the repository `URL`: sftp://USER@HOST[:PORT]/PATH (with /~/PATH relative to the login directory), a local directory or file:///PATH"
	if readOnly {
		usage += "; for reading also https://HOST/PATH"
	}
	fs.String("remote", "", usage)
}

// accessFlags registers the options with which wdyapt logs in to the SFTP
// storage and checks its host key.
func accessFlags(fs *flag.FlagSet, timeout time.Duration) {
	fs.String("password-file", "", "read the SFTP password from `FILE` (or set WDYAPT_SFTP_PASSWORD)")
	fs.String("identity", "", "private SSH key `FILE` (OpenSSH or PEM format, not encrypted)")
	fs.Bool("no-agent", false, "do not use the ssh-agent named by SSH_AUTH_SOCK")
	fs.String("known-hosts", "~/.ssh/known_hosts", "known_hosts `FILE` that confirms the host key of the server")
	fs.String("host-key", "", "expected host key `FINGERPRINT`s (SHA256:...), separated by commas, instead of known_hosts")
	fs.Duration("timeout", timeout, "give up after this `DURATION` in total")
}

var accessEnv = map[string]string{
	"remote":        "WDYAPT_REMOTE",
	"password-file": "WDYAPT_SFTP_PASSWORD_FILE",
	"identity":      "WDYAPT_IDENTITY",
	"known-hosts":   "WDYAPT_KNOWN_HOSTS",
	"host-key":      "WDYAPT_HOST_KEY",
}

var accessSecrets = []cli.Secret{
	{Variable: "WDYAPT_SFTP_PASSWORD", Help: "the password of the SFTP user; used for password and keyboard-interactive login"},
	{Variable: "SSH_AUTH_SOCK", Help: "the socket of a running ssh-agent whose keys are tried for login, unless --no-agent is given"},
}

// signingFlags registers the signing keys and their passphrase.
func signingFlags(fs *flag.FlagSet) {
	fs.Var(&cli.List{Sep: ":"}, "signing-key", "secret OpenPGP key `FILE` to sign the repository with; repeat it to sign with several keys during a key change")
	fs.String("passphrase-file", "", "read the passphrase of the signing keys from `FILE` (or set WDYAPT_SIGNING_KEY_PASSPHRASE)")
}

var signingEnv = map[string]string{
	"signing-key":     "WDYAPT_SIGNING_KEY",
	"passphrase-file": "WDYAPT_SIGNING_KEY_PASSPHRASE_FILE",
}

var signingSecrets = []cli.Secret{
	{Variable: "WDYAPT_SIGNING_KEY_PASSPHRASE", Help: "the passphrase that protects the signing keys"},
}

// trustedFlag registers --trusted-key.
func trustedFlag(fs *flag.FlagSet, usage string) {
	fs.Var(&cli.List{Sep: ":"}, "trusted-key", usage)
}

var trustedEnv = map[string]string{"trusted-key": "WDYAPT_TRUSTED_KEYS"}

// envOf merges the mappings of options to environment variables.
func envOf(parts ...map[string]string) map[string]string {
	m := map[string]string{}
	for _, p := range parts {
		maps.Copy(m, p)
	}
	return m
}

// secretsOf merges secrets.
func secretsOf(parts ...[]cli.Secret) []cli.Secret {
	var s []cli.Secret
	for _, p := range parts {
		s = append(s, p...)
	}
	return s
}
