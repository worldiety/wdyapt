#!/usr/bin/env bash
# Runs the E2E tests in the testbed: an Ubuntu container with OpenSSH,
# GnuPG, dpkg and apt. The tests run in it as root, create users, start
# sshd and install packages; hence only there.
#
#   run.sh [go test arguments …]     (default: -tags e2e -count=1 -v ./e2e/...)
#
# UBUNTU selects the version (26.04 or 24.04), KEEP=1 keeps the container
# after the run.
set -euo pipefail

UBUNTU="${UBUNTU:-26.04}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
image="wdyapt-testbed:$UBUNTU"
name="wdyapt-testbed-${UBUNTU//./}-$$"

if ! command -v docker >/dev/null 2>&1; then
	echo "The E2E testbed needs Docker, but docker is not in PATH." >&2
	exit 2
fi
if ! docker info >/dev/null 2>&1; then
	echo "The E2E testbed needs a running Docker daemon; start it and try again." >&2
	exit 2
fi

args=("$@")
if [ ${#args[@]} -eq 0 ]; then
	args=(-tags e2e -count=1 -v ./e2e/...)
fi

# The same Go version as on the host, so that the caches match.
gover="$(go env GOVERSION)"
gover="${gover#go}"
modcache="$(go env GOMODCACHE)"
(cd "$root" && go mod download)

echo "Building $image (Ubuntu $UBUNTU, Go $gover) …"
docker build -q -t "$image" --build-arg "UBUNTU=$UBUNTU" --build-arg "GO=$gover" "$here" >/dev/null
docker volume create wdyapt-testbed-gocache >/dev/null

cleanup() {
	if [ "${KEEP:-}" = 1 ]; then
		echo "Keeping the container $name; remove it with: docker rm -f $name"
	else
		docker rm -f "$name" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

docker run -d --name "$name" \
	-v "$root:/src:ro" -v "$modcache:/go/pkg/mod:ro" \
	-v wdyapt-testbed-gocache:/root/.cache/go-build \
	-e WDYAPT_TESTBED=1 -e UBUNTU="$UBUNTU" \
	"$image" sleep infinity >/dev/null
docker exec -w /src "$name" go test "${args[@]}"
