package dec

import "github.com/worldiety/speclink/spec"

var RDecAtomicPublishing = spec.Declare(spec.Requirement{
	ID:         "R-DEC-ATOMIC-PUBLISHING",
	Kind:       spec.Decision,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "Safe switching",
	Text:       `A publication MUST first upload new pool files, then package lists and Release under temporary names, and finally move them into place by renaming, InRelease last; a half-written file MUST NEVER lie under a final name.`,
	Rationale: `apt reads InRelease first and follows the checksums named in it. If all new
packages and lists are ready before InRelease changes, a machine sees either
the old or the new state. Renaming on the storage is atomic per file, writing
is not.`,
	Consequences: `Switching several files is not atomic as a whole: if a run stops in the
middle of the renames, apt reports checksum errors until the next run; a new
run completes the state. Interrupted runs can leave temporary files and pool
files that nothing names.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "safe-switching"},
		{Doc: "requirements/_sources/assignment.md", Anchor: "sftp-in-the-tool"},
	},
})
