package pkg

import "github.com/worldiety/speclink/spec"

var RPkgControlData = spec.Declare(spec.Requirement{
	ID:         "R-PKG-CONTROL-DATA",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Control data of a package",
	Text:       `A built package MUST contain a control file with Package, Version, Architecture, Maintainer, Installed-Size, the given package relations, Section, Priority and Description, as well as md5sums, conffiles and the given maintainer scripts.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "describing-packages"},
	},
})
