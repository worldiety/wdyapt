package key

import "github.com/worldiety/speclink/spec"

var RKeyExportAndShow = spec.Declare(spec.Requirement{
	ID:         "R-KEY-EXPORT-AND-SHOW",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Export and show keys",
	Text:       `wdyapt key export MUST write the public key in binary form for Signed-By or ASCII armored; wdyapt key show MUST show fingerprint, user IDs, algorithm, expiry, subkeys with capabilities and the protection of the secret part.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "signing-in-the-tool"},
	},
})
