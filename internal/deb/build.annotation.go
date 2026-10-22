package deb

import (
	"github.com/worldiety/speclink/spec"
	reqpkg "github.com/worldiety/wdyapt/requirements/fun/pkg"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

var _ = spec.ForDecl(Build,
	spec.Satisfies(reqpkg.RPkgBuildFromFiles, reqpkg.RPkgControlData, nfr.RNfrReproducibility),
)
