package deb

import (
	"github.com/worldiety/speclink/spec"
	reqpkg "github.com/worldiety/wdyapt/requirements/fun/pkg"
)

var _ = spec.ForDecl(Validate,
	spec.Satisfies(reqpkg.RPkgValidateInput),
)
