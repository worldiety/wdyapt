package ssh

import (
	"github.com/worldiety/speclink/spec"
	"github.com/worldiety/wdyapt/requirements/dec"
)

var _ = spec.ForPackage(
	spec.Satisfies(dec.RDecSshAndSftpInProcess),
)
