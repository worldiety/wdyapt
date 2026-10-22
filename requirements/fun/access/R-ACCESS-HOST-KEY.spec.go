package access

import "github.com/worldiety/speclink/spec"

var RAccessHostKey = spec.Declare(spec.Requirement{
	ID:         "R-ACCESS-HOST-KEY",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Check the host key",
	Text:       `wdyapt MUST always check the host key against known_hosts or a given fingerprint, MUST NEVER accept an unknown key and MUST be able to fetch the host keys of a server for known_hosts.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "access-to-the-storage"},
	},
})
