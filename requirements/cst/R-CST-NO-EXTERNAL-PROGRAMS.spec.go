package cst

import "github.com/worldiety/speclink/spec"

var RCstNoExternalPrograms = spec.Declare(spec.Requirement{
	ID:         "R-CST-NO-EXTERNAL-PROGRAMS",
	Kind:       spec.Constraint,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "No external programs",
	Text:       `wdyapt MUST NOT start other programs; building packages, signing, verifying and transferring files MUST happen in its own process.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "no-dependencies"},
		{Doc: "requirements/_sources/assignment.md", Anchor: "sftp-in-the-tool"},
	},
})
