package pkg

import "github.com/worldiety/speclink/spec"

var RPkgValidateInput = spec.Declare(spec.Requirement{
	ID:         "R-PKG-VALIDATE-INPUT",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Validate inputs before building",
	Text:       `Before building, wdyapt MUST check name, version, architecture, maintainer, target paths, modes, conffiles and maintainer scripts and whether every ELF program fits the architecture of the package, and report all problems together without writing a package.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "describing-packages"},
	},
})
