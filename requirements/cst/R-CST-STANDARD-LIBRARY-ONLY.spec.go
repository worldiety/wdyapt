package cst

import "github.com/worldiety/speclink/spec"

var RCstStandardLibraryOnly = spec.Declare(spec.Requirement{
	ID:         "R-CST-STANDARD-LIBRARY-ONLY",
	Kind:       spec.Constraint,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "Go standard library only",
	Text:       `wdyapt MUST be built with the Go standard library only and without CGO; the only exception is the module github.com/worldiety/speclink/spec, which itself uses only the standard library. A test MUST check the dependency graph of the program and the requirements in go.mod.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "no-dependencies"},
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "speclink-as-the-only-exception"},
	},
})
