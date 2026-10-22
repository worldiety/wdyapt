package store

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

// The requirement is bound to the storage as a whole: credentials live only
// in the authentication methods; Describe and all messages never name them.
var _ = spec.ForPackage(
	spec.Satisfies(nfr.RNfrConfidentialCredentials),
)
