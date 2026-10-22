package knownhosts

import (
	"github.com/worldiety/speclink/spec"
	reqaccess "github.com/worldiety/wdyapt/requirements/fun/access"
)

var _ = spec.ForPackage(
	spec.Satisfies(reqaccess.RAccessHostKey),
)
