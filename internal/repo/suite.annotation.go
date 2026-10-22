package repo

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/fun/repo"
)

var _ = spec.ForDecl(ReadSuite,
	spec.Satisfies(repo.RRepoCheckState),
)
