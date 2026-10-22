package pkg

import "github.com/worldiety/speclink/spec"

var RPkgShow = spec.Declare(spec.Requirement{
	ID:         "R-PKG-SHOW",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Show packages",
	Text:       `wdyapt deb info MUST show for a Debian package its control data, conffiles, maintainer scripts, the list of files with mode and size as well as size, SHA256 and file name in the pool, as JSON on request.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "describing-packages"},
	},
})
