package store

import (
	"github.com/worldiety/speclink/spec"
	reqaccess "github.com/worldiety/wdyapt/requirements/fun/access"
)

var _ = spec.ForDecl(Check,
	spec.Satisfies(reqaccess.RAccessCheck),
)
