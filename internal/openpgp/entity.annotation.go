package openpgp

import (
	"github.com/worldiety/speclink/spec"
	reqkey "github.com/worldiety/wdyapt/requirements/fun/key"
)

var _ = spec.ForDecl(ReadKeys,
	spec.Satisfies(reqkey.RKeyUseGnupgKeys),
)

var _ = spec.ForDecl(Export,
	spec.Satisfies(reqkey.RKeyExportAndShow),
)
