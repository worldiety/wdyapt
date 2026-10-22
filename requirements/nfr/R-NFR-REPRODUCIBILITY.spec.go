package nfr

import "github.com/worldiety/speclink/spec"

var RNfrReproducibility = spec.Declare(spec.Requirement{
	ID:         "R-NFR-REPRODUCIBILITY",
	Kind:       spec.NonFunctional,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "Reproducible results",
	Text:       `The same inputs and the same timestamp MUST produce byte for byte the same package with the same Go version; the same state, the same packages and the same date MUST produce the same package lists and the same Release.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "reproducibility"},
	},
})
