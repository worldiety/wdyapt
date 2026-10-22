# The recipes of wdyapt. `just` without a recipe lists them.
set shell := ["bash", "-eo", "pipefail", "-c"]
set script-interpreter := ["bash", "-euo", "pipefail"]
set lazy

BUILD := "build"
SPECLINK := env("SPECLINK", "speclink")
SPECLINK_VERSION := "v0.0.0-20261013170042-95355e973f31"
VERSION_PKG := "github.com/worldiety/wdyapt/internal/version"
BASE_VERSION := `cat VERSION`
COMMIT_TIMESTAMP := env("COMMIT_TIMESTAMP", `TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d%H%M%S HEAD 2>/dev/null || true`)
BUILD_COMMIT := env("BUILD_COMMIT", `git rev-parse --short=8 HEAD 2>/dev/null || true`)
FULL_VERSION := env("FULL_VERSION", BASE_VERSION + "~dev." + COMMIT_TIMESTAMP + "." + BUILD_COMMIT)
SOURCE_DATE_EPOCH := env("SOURCE_DATE_EPOCH", `git show -s --format=%ct HEAD 2>/dev/null || true`)
TEST_JSON := env("TEST_JSON", "")
UBUNTU := env("UBUNTU", "26.04")
OSES := "linux darwin"
ARCHES := "amd64 arm64"

[doc("Show all recipes with explanations")]
help:
    @"{{ just_executable() }}" --justfile "{{ justfile() }}" --list --unsorted

[doc("Install speclink in the pinned version")]
tools:
    go install github.com/worldiety/speclink/cmd/speclink@{{ SPECLINK_VERSION }}

[doc("gofmt and go vet, including the E2E tests")]
lint:
    @files="$(gofmt -l $(git ls-files --cached --others --exclude-standard '*.go'))"; \
    if [ -n "$files" ]; then printf 'not formatted with gofmt:\n%s\n' "$files"; exit 1; fi
    go vet ./...
    go vet -tags e2e ./e2e/...

[doc("All tests with the race detector")]
test:
    go test -race -count=1 ./...

[doc("Check the requirement tree alone")]
requirements:
    {{ SPECLINK }} requirements -root . ./requirements/...

[doc("Check the requirements, then an evidence run of all tests")]
verify: && evidence-check
    {{ SPECLINK }} verify -root . ./...

# As in wdyhub: back up the lock file, feed the tests to speclink, restore
# it on failure; afterwards the lock file must not differ.
[doc("Feed all tests to speclink; fails if speclink.lock differs afterwards")]
[script]
evidence-check:
    before=$(mktemp); run=$(mktemp); trap 'rm -f "$before" "$run"' EXIT
    json="{{ TEST_JSON }}"
    if [ -n "$json" ]; then mkdir -p "$(dirname "$json")"; fi
    if [ -f speclink.lock ]; then cp speclink.lock "$before"; else : > "$before"; fi
    if ! go test -count=1 -timeout 30m -json ./... | tee "$run" ${json:+"$json"} | {{ SPECLINK }} evidence -root .; then
        if [ -s "$before" ]; then cp "$before" speclink.lock; fi
        { grep '"Action":"fail"' "$run" || true; } | sed -E 's/.*"Package":"([^"]*)"(,"Test":"([^"]*)")?.*/FAIL \1 \3/' | sort -u >&2
        echo "the test run failed; speclink.lock stays as it was before" >&2
        exit 1
    fi
    if [ -s "$before" ] && ! cmp -s "$before" speclink.lock; then
        diff -u "$before" speclink.lock || true
        echo "speclink.lock does not match this test run; review the new version and commit it too" >&2
        exit 1
    fi

[doc("Specification as Markdown  (build/SPECIFICATION.md)")]
spec:
    @mkdir -p {{ BUILD }}
    {{ SPECLINK }} generate -root . -out {{ BUILD }}/SPECIFICATION.md ./...

[doc("Build wdyapt for this system  (build/bin/wdyapt)")]
build:
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X {{ VERSION_PKG }}.current={{ FULL_VERSION }}" -o {{ BUILD }}/bin/wdyapt ./cmd/wdyapt

[doc("For linux and darwin, amd64 and arm64  (build/bin/<os>_<arch>/)")]
[script]
build-cross:
    for os in {{ OSES }}; do for arch in {{ ARCHES }}; do
        out="{{ BUILD }}/bin/${os}_$arch/"; mkdir -p "$out"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
            -ldflags "-s -w -X {{ VERSION_PKG }}.current={{ FULL_VERSION }}" -o "$out" ./cmd/wdyapt
    done; done

[doc("Build twice (second build with an empty cache) and compare")]
[script]
release-check:
    just build-cross && rm -rf {{ BUILD }}/first && mv {{ BUILD }}/bin {{ BUILD }}/first
    GOCACHE="$(mktemp -d)" just build-cross
    (cd {{ BUILD }}/first && find . -type f -exec sha256sum {} +) | sort > {{ BUILD }}/first.sha256
    (cd {{ BUILD }}/bin && sha256sum -c ../first.sha256)

[doc("E2E tests in the Docker testbed (UBUNTU=24.04 checks the older version)")]
test-e2e:
    UBUNTU="{{ UBUNTU }}" e2e/testbed/run.sh -tags e2e -count=1 -v ./e2e/...

[doc("E2E tests on Ubuntu 24.04 and 26.04")]
test-e2e-all:
    just UBUNTU=24.04 test-e2e
    just UBUNTU=26.04 test-e2e

[doc("Check dependencies against the allowed exception")]
deps-check:
    go test -count=1 ./internal/depcheck

[doc("Empty the build directory")]
clean:
    rm -rf {{ BUILD }}
