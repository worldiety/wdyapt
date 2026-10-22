package dec

import "github.com/worldiety/speclink/spec"

var RDecSshAndSftpInProcess = spec.Declare(spec.Requirement{
	ID:         "R-DEC-SSH-AND-SFTP-IN-PROCESS",
	Kind:       spec.Decision,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "SSH and SFTP in the tool",
	Text:       `wdyapt MUST implement SSH-2 and SFTP version 3 itself and carry out all file operations on the storage in its own process; it uses only current algorithms without SHA-1 and CBC, protects the key exchange with strict kex and replaces files atomically through posix-rename where the server offers it.`,
	Rationale: `The assignment requires the tool to speak SFTP itself and forbids external
programs such as ssh and sftp. The Go standard library contains no SSH, and
golang.org/x/crypto/ssh is ruled out as an external dependency. The standard
library provides the necessary building blocks (ECDH, ML-KEM, AES-GCM,
AES-CTR, HMAC, Ed25519, ECDSA, RSA); the protocol can be built on them.`,
	Consequences: `wdyapt carries its own implementation of a security-critical protocol that
has to be maintained and checked against OpenSSH. What the standard library
cannot do is missing: chacha20-poly1305 and encrypted OpenSSH private keys
(bcrypt-pbkdf). A test server of its own and an E2E testbed with OpenSSH
secure the implementation.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "sftp-in-the-tool"},
	},
})
