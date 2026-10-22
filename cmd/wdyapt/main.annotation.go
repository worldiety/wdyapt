package main

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/cst"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

// Bound is the program as a whole: what it imports and what it is built
// for is verified by internal/depcheck on exactly this package.
var _ = spec.ForPackage(
	spec.Satisfies(cst.RCstStandardLibraryOnly, cst.RCstNoExternalPrograms, nfr.RNfrPlatforms, nfr.RNfrSelfExplainingCli, nfr.RNfrHumansAndPipelines, nfr.RNfrConfidentialCredentials),
)
