# SOCKS5 exit for the SSH-over-dnstt mobile clients. microsocks is not in the
# Alpine repositories, so it is built from source; loopback-only and
# unauthenticated, because the only route to it is an authenticated SSH forward
# through the tunnel.
#
# Pinned for the reason spelled out in dnstt/Dockerfile: composectl.up passes
# `--build`, and `apply` runs unattended from the boot unit, so anything that
# floats is re-resolved on a live server at a moment nobody chose. This was
# `git clone --depth 1` of whatever HEAD happened to be.
#
# The pin is the COMMIT, not the tag: a tag can be moved, and a moved tag is
# precisely the silent substitution the pin exists to stop. The clone still
# asks for the tag -- it is the cheap way to fetch one commit -- and then
# asserts the sha, so a moved tag FAILS the build loudly instead of quietly
# building something else.
ARG MICROSOCKS_VERSION=v1.0.5
ARG MICROSOCKS_COMMIT=98421a21c4adc4c77c0cf3a5d650cc28ad3e0107
# Tag and digest in one reference: docker resolves by the digest, the tag is
# there for a human. The multi-arch index digest, so it holds on another
# architecture.
ARG ALPINE_IMAGE=alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

FROM ${ALPINE_IMAGE} AS build
ARG MICROSOCKS_VERSION
ARG MICROSOCKS_COMMIT
RUN apk add --no-cache git build-base \
 && git clone --depth 1 --branch "${MICROSOCKS_VERSION}" \
      https://github.com/rofl0r/microsocks /src \
 && head="$(git -C /src rev-parse HEAD)" \
 && if [ "$head" != "${MICROSOCKS_COMMIT}" ]; then \
      echo "microsocks ${MICROSOCKS_VERSION} is $head, not the pinned ${MICROSOCKS_COMMIT}" >&2; \
      echo "the tag moved -- review upstream and update MICROSOCKS_COMMIT deliberately" >&2; \
      exit 1; \
    fi \
 && make -C /src

FROM ${ALPINE_IMAGE}
ARG MICROSOCKS_VERSION
ARG MICROSOCKS_COMMIT
LABEL org.opencontainers.image.title="microsocks" \
      org.opencontainers.image.version="${MICROSOCKS_VERSION}" \
      org.opencontainers.image.revision="${MICROSOCKS_COMMIT}" \
      org.opencontainers.image.source="https://github.com/rofl0r/microsocks"
COPY --from=build /src/microsocks /usr/local/bin/microsocks
# A uid to run as, so compose can drop root on a process that needs nothing:
# it binds one high loopback port and opens outbound sockets. compose.yml names
# the number, not this name, because a numeric `user:` cannot fail an
# /etc/passwd lookup at container-create time -- keep the two in step.
RUN addgroup -S -g 10300 microsocks \
 && adduser -S -D -H -u 10300 -G microsocks -s /sbin/nologin microsocks
ENTRYPOINT ["/usr/local/bin/microsocks"]
