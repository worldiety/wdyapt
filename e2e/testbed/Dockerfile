# Testbed for the wdyapt E2E tests: Ubuntu with OpenSSH, GnuPG, gpgv, sqv,
# dpkg and apt, plus the Go toolchain. run.sh builds it and runs
# "go test -tags e2e" in it as root. UBUNTU selects the version: 26.04
# (OpenSSH 10, apt 3 with sqv) is the default, 24.04 (OpenSSH 9.6, apt 2.8
# with gpgv) checks the older one.
ARG UBUNTU=26.04
ARG GO=1.27.3
FROM golang:${GO} AS go

FROM ubuntu:${UBUNTU}
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      openssh-server openssh-client gnupg gpgv sqv ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources \
 && mkdir -p /run/sshd
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly GOMODCACHE=/go/pkg/mod
