package deb

import (
	"github.com/worldiety/speclink/spec"
	reqpkg "github.com/worldiety/wdyapt/requirements/fun/pkg"
)

var _ = spec.ForDecl(Read,
	spec.Satisfies(reqpkg.RPkgShow),
)
