package nfr

import "github.com/worldiety/speclink/spec"

var RNfrHumansAndPipelines = spec.Declare(spec.Requirement{
	ID:         "R-NFR-HUMANS-AND-PIPELINES",
	Kind:       spec.NonFunctional,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "For humans and pipelines",
	Text:       `wdyapt MUST NOT ask interactively; every option with a sensible environment value MUST be settable through a WDYAPT_* environment variable, and secrets only through the environment or files. Results MUST go to standard output, as JSON on request, progress and errors to standard error; the exit codes MUST be 0 for success, 1 for errors, 2 for wrong usage and 75 for temporary obstacles.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "humans-and-pipelines"},
	},
})
