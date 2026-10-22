package key

import "github.com/worldiety/speclink/spec"

var RKeyRotation = spec.Declare(spec.Requirement{
	ID:         "R-KEY-ROTATION",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Key rotation",
	Text:       `For a key change, wdyapt MUST sign with several signing keys at once and accept further trusted public keys the published state may be signed with.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "signing-in-the-tool"},
	},
})
