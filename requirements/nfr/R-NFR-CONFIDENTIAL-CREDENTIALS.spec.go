package nfr

import "github.com/worldiety/speclink/spec"

var RNfrConfidentialCredentials = spec.Declare(spec.Requirement{
	ID:         "R-NFR-CONFIDENTIAL-CREDENTIALS",
	Kind:       spec.NonFunctional,
	Discipline: spec.Technical,
	Status:     spec.Normative,
	Title:      "Confidential credentials",
	Text:       `SFTP passwords, passphrases and secret keys MUST NOT appear in any output, error message, JSON output, verbose progress message or the lock file.`,
	Sources: []spec.Source{
		{Doc: "requirements/_sources/clarification-of-decisions.md", Anchor: "access-to-the-storage"},
	},
})
