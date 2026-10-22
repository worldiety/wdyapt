// Package depcheck contains no code, only tests: they verify that wdyapt
// imports only the Go standard library and
// github.com/worldiety/speclink/spec (R-CST-STANDARD-LIBRARY-ONLY), starts
// no other programs (R-CST-NO-EXTERNAL-PROGRAMS) and builds without CGO for
// Linux and macOS on amd64 and arm64 (R-NFR-PLATFORMS).
package depcheck
