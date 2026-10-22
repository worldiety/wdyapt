package repo

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/fun/repo"
	"github.com/worldiety/wdyapt/requirements/nfr"
)

var _ = spec.ForDecl(Merge,
	spec.Satisfies(repo.RRepoNeverReplace, repo.RRepoKeepReleaseFields, nfr.RNfrReproducibility),
)
