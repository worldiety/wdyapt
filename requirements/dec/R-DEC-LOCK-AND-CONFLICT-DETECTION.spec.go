package dec

import "github.com/worldiety/speclink/spec"

var RDecLockAndConflictDetection = spec.Declare(spec.Requirement{
	ID:         "R-DEC-LOCK-AND-CONFLICT-DETECTION",
	Kind:       spec.Decision,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "Lock and conflict detection",
	Text:       `A publication MUST create a lock file exclusively on the storage and check before switching whether the state of the suite changed since it was read; in both cases of conflict it MUST end without switching with exit code 75 so that a pipeline can repeat the run.`,
	Rationale: `Two concurrent runs read the same state and would overwrite each other's
package lists. An SFTP storage knows no locks; creating a file exclusively is
the only available means. The second check detects tools that do not know the
lock.`,
	Consequences: `An interrupted run can leave a lock that has to be removed by hand or with
--break-lock. A foreign tool that uploads an older state shortly after the
switch is not detected; that needs a shared resource_group in the pipeline.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "concurrent-publishing"},
	},
})
