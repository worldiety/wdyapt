// Package version provides the version of wdyapt.
//
// The build sets the value with:
//
//	-ldflags "-X github.com/worldiety/wdyapt/internal/version.current=..."
//
// Without that, the module version "go install …@vX.Y.Z" built with applies,
// otherwise "devel". The version appears in the SSH identification and in
// the lock file.
package version

import "runtime/debug"

// current is set by the build through the linker.
var current string

// String returns the version of the running program.
func String() string {
	if current != "" {
		return current
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "devel"
}
