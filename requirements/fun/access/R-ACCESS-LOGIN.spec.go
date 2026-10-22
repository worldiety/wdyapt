package access

import "github.com/worldiety/speclink/spec"

var RAccessLogin = spec.Declare(spec.Requirement{
	ID:         "R-ACCESS-LOGIN",
	Kind:       spec.Functional,
	Discipline: spec.Business,
	Status:     spec.Normative,
	Title:      "Login to the storage",
	Text:       `wdyapt MUST be able to log in to the SFTP storage with a password, keyboard-interactive, a key file or through the ssh-agent.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "access-to-the-storage"},
	},
})
