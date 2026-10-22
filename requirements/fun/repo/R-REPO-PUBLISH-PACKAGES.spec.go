package repo

import "github.com/worldiety/speclink/spec"

var RRepoPublishPackages = spec.Declare(spec.Requirement{
	ID:         "R-REPO-PUBLISH-PACKAGES",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Publish packages",
	Text:       `wdyapt publish MUST add packages to a suite and component of an APT repository, place them in the pool and write package lists and Release anew; packages of the architecture all MUST appear in every package list of the suite, and a suite that does not exist yet MAY only be created with --create.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "ship-arbitrary-programs"},
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "continue-the-existing-repository"},
	},
})
