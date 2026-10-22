package repo

import "github.com/worldiety/speclink/spec"

var RRepoSign = spec.Declare(spec.Requirement{
	ID:         "R-REPO-SIGN",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Sign the Release",
	Text:       `wdyapt MUST sign every new Release as InRelease and Release.gpg with all given signing keys and SHA-512; the Date of the new Release MUST lie after that of the previous state.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "signing-in-the-tool"},
	},
})
