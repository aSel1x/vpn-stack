# SOCKS5 exit for SSH-over-dnstt mobile clients. microsocks built from source
# (not in alpine repos); loopback-only, no auth needed behind the SSH gate.
FROM alpine:3.20 AS build
RUN apk add --no-cache git build-base \
 && git clone --depth 1 https://github.com/rofl0r/microsocks /src \
 && make -C /src
FROM alpine:3.20
COPY --from=build /src/microsocks /usr/local/bin/microsocks
ENTRYPOINT ["/usr/local/bin/microsocks"]
