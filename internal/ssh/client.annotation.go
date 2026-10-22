package ssh

import (
	"github.com/worldiety/speclink/spec"
	reqaccess "github.com/worldiety/wdyapt/requirements/fun/access"
)

var _ = spec.ForDecl(Dial,
	spec.Satisfies(reqaccess.RAccessLogin),
)
