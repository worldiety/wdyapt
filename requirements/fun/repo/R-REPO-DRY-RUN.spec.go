package repo

import "github.com/worldiety/speclink/spec"

var RRepoDryRun = spec.Declare(spec.Requirement{
	ID:         "R-REPO-DRY-RUN",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Dry run",
	Text:       `With --dry-run, wdyapt publish MUST show what it would add, upload and sign without writing anything to the storage.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "trying-without-effect"},
	},
})
