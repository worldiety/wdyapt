package dec

import "github.com/worldiety/speclink/spec"

var RDecNoDeletion = spec.Declare(spec.Requirement{
	ID:         "R-DEC-NO-DELETION",
	Kind:       spec.Decision,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "No deletion of published packages",
	Text:       `wdyapt MUST NOT delete published packages, remove entries from package lists or apply a retention rule; on the storage it removes only its own temporary files and its own lock.`,
	Rationale: `The assignment does not need the deletion logic of the old tool. A tool
that never deletes cannot lose packages machines still use, and a mistake in a
retention rule cannot do any harm.`,
	Consequences: `The repository grows with every version. Cleaning up remains manual work on
the storage; afterwards the suite has to be signed consistently again by a new
run. A wrongly published package can only be superseded by a new version.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "no-deletion-of-uploaded-artifacts"},
	},
})
