package pkg

import "github.com/worldiety/speclink/spec"

var RPkgBuildFromFiles = spec.Declare(spec.Requirement{
	ID:         "R-PKG-BUILD-FROM-FILES",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Build packages from files",
	Text:       `wdyapt deb build MUST build, from existing files described by options or a JSON manifest, one Debian binary package per given architecture that dpkg accepts; source paths MAY contain the placeholders {arch} and {uname}.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/assignment.md", Anchor: "ship-arbitrary-programs"},
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "describing-packages"},
	},
})
