package repo

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/fun/repo"
)

var _ = spec.ForDecl(List,
	spec.Satisfies(repo.RRepoList),
)

var _ = spec.ForDecl(Verify,
	spec.Satisfies(repo.RRepoVerify),
)
