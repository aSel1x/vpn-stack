# dnstt-server, the DNS tunnel's server half. Built from source because upstream
# ships no binaries and no distribution packages it.
#
# Every input here is pinned, and the reason is sharper than general hygiene:
# composectl.up passes `--build`, and `apply` runs from `user add`, `user rm`,
# `protocol on`, `protocol off`, `deploy` and the vpn-stack.service boot unit.
# So an unpinned input is re-resolved on a live server at a moment nobody chose
# -- unattended, at boot. This file said `go install ...@latest`, which meant a
# rebuild that missed the BuildKit cache could serve different code than the
# last one, with nothing recording what the last one was and no tag to roll
# back to. That is the same class of accident the candidate-tree design in
# `apply` exists to prevent, and it was the one hole left in it.
#
# Bump deliberately: change the version here, rebuild, and prove the tunnel
# still comes up before this reaches a server people are using.
ARG DNSTT_VERSION=v1.20260501.0
# Tag and digest in one reference: docker resolves by the digest and the tag is
# there for a human, the same arrangement hwdsl2/ipsec-vpn-server has in
# compose.yml. Both are the multi-arch index digest, so the pin still resolves
# on a server of another architecture.
ARG GOLANG_IMAGE=golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f
ARG ALPINE_IMAGE=alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

FROM ${GOLANG_IMAGE} AS build
ARG DNSTT_VERSION
# The module's own go directive is `go 1.21` (proxy.golang.org, the .mod for
# this version), so the 1.23 toolchain builds it without downloading another
# one -- which matters because a toolchain download is a second unpinned fetch
# hiding inside a pinned build.
#
# The version is an ARG rather than a literal in this line so that one edit
# moves both the build and the LABEL below, and `docker inspect` can answer
# "what is actually running" without anyone reading this file.
RUN go install "www.bamsoftware.com/git/dnstt.git/dnstt-server@${DNSTT_VERSION}"

FROM ${ALPINE_IMAGE}
ARG DNSTT_VERSION
LABEL org.opencontainers.image.title="dnstt-server" \
      org.opencontainers.image.version="${DNSTT_VERSION}" \
      org.opencontainers.image.source="https://www.bamsoftware.com/software/dnstt/"
COPY --from=build /go/bin/dnstt-server /usr/local/bin/dnstt-server
# Stays root. It binds udp/53 in the host's network namespace, and compose
# hands it NET_BIND_SERVICE and nothing else; a non-root uid would need that
# capability as a file capability on the binary, which buys nothing over an
# empty capability set on a process that opens one socket and reads one key.
ENTRYPOINT ["/usr/local/bin/dnstt-server"]
