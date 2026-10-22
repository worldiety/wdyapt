package key

import "github.com/worldiety/speclink/spec"

var RKeyUseGnupgKeys = spec.Declare(spec.Requirement{
	ID:         "R-KEY-USE-GNUPG-KEYS",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Use keys from GnuPG",
	Text:       `wdyapt MUST read secret OpenPGP keys exported by GnuPG, with Ed25519 or RSA, unprotected or protected with iterated and salted S2K, and sign with the matching primary key or subkey; it MUST recognise keys without a secret part as such.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "signing-in-the-tool"},
	},
})
