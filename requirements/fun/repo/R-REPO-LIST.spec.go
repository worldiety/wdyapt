package repo

import "github.com/worldiety/speclink/spec"

var RRepoList = spec.Declare(spec.Requirement{
	ID:         "R-REPO-LIST",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "List the packages of a suite",
	Text:       `wdyapt repo list MUST list the packages of a suite with name, version, architecture, size and pool path, as JSON on request.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "humans-and-pipelines"},
	},
})
