package access

import "github.com/worldiety/speclink/spec"

var RAccessCheck = spec.Declare(spec.Requirement{
	ID:         "R-ACCESS-CHECK",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Check the access",
	Text:       `wdyapt remote check MUST connect to the storage and report host key, login method, SFTP extensions and the suites found, without changing anything.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "access-to-the-storage"},
	},
})
