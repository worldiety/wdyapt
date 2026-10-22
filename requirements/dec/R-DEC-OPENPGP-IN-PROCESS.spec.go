package dec

import "github.com/worldiety/speclink/spec"

var RDecOpenpgpInProcess = spec.Declare(spec.Requirement{
	ID:         "R-DEC-OPENPGP-IN-PROCESS",
	Kind:       spec.Decision,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "OpenPGP in the tool",
	Text:       `wdyapt MUST sign the repository itself according to OpenPGP (RFC 9580, version 4 keys and signatures) with Ed25519 or RSA and SHA-512 and verify signatures itself, without gpg or gpgv.`,
	Rationale: `External programs are forbidden, and so are gpg and gpgv. The standard
library provides Ed25519, RSA, SHA-2 and AES; the OpenPGP packet format and the
cleartext signature can be written on top of them with moderate effort, as
long as only version 4 keys and signatures are supported, as GnuPG creates them
by default.`,
	Consequences: `Version 5 and 6 keys, AEAD and Argon2 protection and encryption are not
supported and result in an error message with a way out. Interoperability with
GnuPG, gpgv and sqv has to be shown with test data made by GnuPG and the E2E
testbed.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "signing-in-the-tool"},
	},
})
