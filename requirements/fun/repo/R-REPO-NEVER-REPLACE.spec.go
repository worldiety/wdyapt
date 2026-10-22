package repo

import "github.com/worldiety/speclink/spec"

var RRepoNeverReplace = spec.Declare(spec.Requirement{
	ID:         "R-REPO-NEVER-REPLACE",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Never replace published packages",
	Text:       `A published package MUST NEVER be replaced by another one with the same name, version and architecture; publishing the same content again MUST end without change and without error.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "continue-the-existing-repository"},
	},
})
