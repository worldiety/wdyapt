package repo

import "github.com/worldiety/speclink/spec"

var RRepoKeepReleaseFields = spec.Declare(spec.Requirement{
	ID:         "R-REPO-KEEP-RELEASE-FIELDS",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Keep the fields of a suite",
	Text:       `In an existing suite, Origin, Label, Suite, Codename, Description, Changelogs and unknown fields of the Release MUST keep their order and value; only Date, Architectures, Components and the checksums are set anew.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "continue-the-existing-repository"},
	},
})
