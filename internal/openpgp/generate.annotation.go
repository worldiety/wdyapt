package openpgp

import (
	"github.com/worldiety/speclink/spec"
	reqkey "github.com/worldiety/wdyapt/requirements/fun/key"
)

var _ = spec.ForDecl(Generate,
	spec.Satisfies(reqkey.RKeyGenerate),
)
