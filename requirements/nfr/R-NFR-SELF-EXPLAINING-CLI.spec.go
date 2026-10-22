package nfr

import "github.com/worldiety/speclink/spec"

var RNfrSelfExplainingCli = spec.Declare(spec.Requirement{
	ID:         "R-NFR-SELF-EXPLAINING-CLI",
	Kind:       spec.NonFunctional,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "Self-explaining command line",
	Text:       `Started without a command, wdyapt MUST state its purpose and its commands on standard output; every command, every option, every placeholder of a positional argument and every environment variable MUST have help that appears on standard output and fits into 80 columns.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "self-explaining-commands"},
	},
})
