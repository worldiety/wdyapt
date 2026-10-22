package nfr

import "github.com/worldiety/speclink/spec"

var RNfrPlatforms = spec.Declare(spec.Requirement{
	ID:         "R-NFR-PLATFORMS",
	Kind:       spec.NonFunctional,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "Linux and macOS on amd64 and arm64",
	Text:       `wdyapt MUST run on Linux and macOS, each on amd64 and arm64, and MUST build for all four platforms without CGO.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "platforms"},
	},
})
