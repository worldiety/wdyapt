package repo

import "github.com/worldiety/speclink/spec"

var RRepoVerify = spec.Declare(spec.Requirement{
	ID:         "R-REPO-VERIFY",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Verify a repository",
	Text:       `wdyapt repo verify MUST check signatures, checksums of the package lists and the pool files of a published repository, report all problems including leftover temporary files and an orphaned lock, and end with exit code 1 if there is a problem.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "continue-the-existing-repository"},
	},
})
