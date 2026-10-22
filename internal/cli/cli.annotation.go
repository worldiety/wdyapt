package cli

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

var _ = spec.ForDecl((*Program).Main,
	spec.Satisfies(nfr.RNfrHumansAndPipelines),
)
