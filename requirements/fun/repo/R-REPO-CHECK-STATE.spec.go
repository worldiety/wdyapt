package repo

import "github.com/worldiety/speclink/spec"

var RRepoCheckState = spec.Declare(spec.Requirement{
	ID:         "R-REPO-CHECK-STATE",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Check the published state",
	Text:       `Before wdyapt changes a suite, it MUST check the signature of its Release against the trusted keys and every package list against size and SHA256 in the Release; it MUST NOT continue from a state it could not check.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "continue-the-existing-repository"},
	},
})
