package key

import "github.com/worldiety/speclink/spec"

var RKeyGenerate = spec.Declare(spec.Requirement{
	ID:         "R-KEY-GENERATE",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Generate keys",
	Text:       `wdyapt key generate MUST create a version 4 OpenPGP signing key with Ed25519 that gpgv on Ubuntu 24.04 and 26.04 accepts, and write the secret key only with mode 0600 and without overwriting an existing file.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "signing-in-the-tool"},
	},
})
