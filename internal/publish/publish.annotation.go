package publish

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/dec"
	reqkey "github.com/worldiety/wdyapt/requirements/fun/key"
	"github.com/worldiety/wdyapt/requirements/fun/repo"
)

var _ = spec.ForDecl(Run,
	spec.Satisfies(
		repo.RRepoPublishPackages, repo.RRepoSign, repo.RRepoDryRun,
		dec.RDecNoDeletion, dec.RDecAtomicPublishing, dec.RDecLockAndConflictDetection,
		reqkey.RKeyRotation,
	),
)
