# The SSH front for the DNS tunnel, in a container rather than on the host.
#
# iOS clients (HTTP Injector, AnyBridge) speak DNSTT -> SSH: they log in over
# the tunnel and forward through it. That needs an sshd and a login. Putting
# both here instead of on the host means no host account, no edit to the host's
# /etc/ssh/sshd_config, and a login whose blast radius is an empty Alpine
# container with nothing mounted but its own config.
#
# It rides network_mode: host, so 127.0.0.1:7300 inside is the microsocks the
# dnstt-socks container binds -- same loopback, one namespace.
#
# Pinned by digest for the reason dnstt/Dockerfile spells out: composectl.up
# passes `--build` and `apply` runs unattended from the boot unit, so a floating
# base image is re-resolved on a live server at a moment nobody chose. Tag and
# digest in one reference: docker resolves by the digest and the tag is there
# for a human, and it is the multi-arch index digest, so it holds on another
# architecture. The openssh version inside still moves with the 3.20 branch --
# that is the point of a stable branch and is a security update, not a feature
# change; the digest fixes the base filesystem, not apk's view of the network.
ARG ALPINE_IMAGE=alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

FROM ${ALPINE_IMAGE}
LABEL org.opencontainers.image.title="dnstt-sshd" \
      org.opencontainers.image.source="https://github.com/aSel1x/vpn-stack"
# No nc package: busybox's own `nc` applet has -z and -w, which is the whole of
# compose.yml's healthcheck for this service. A healthcheck that needed a
# package would be one more thing to pin.
RUN apk add --no-cache openssh-server openssh-sftp-server tini
# Snapshot the accounts this image ships with -- after apk add, so anything a
# package created is in it. The entrypoint refuses to serve a login whose name
# is on this list, and it needs the list recorded here rather than derived at
# run time: once the writable layer has been written to once, /etc/passwd cannot
# tell a baked-in system account apart from an account a previous start of the
# same container created, and the difference decides whether a name is a
# collision to refuse or a login to reuse. See entrypoint.sh for what the
# collision used to do -- it set root's password to somebody's dnstt password
# and gave them no working login in exchange.
RUN cp /etc/passwd /etc/dnstt-sshd.reserved
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
# Stays root, and unlike its two siblings it has to: the entrypoint rewrites
# /etc/passwd, /etc/shadow and /etc/group from the rendered login list on every
# start -- which is the entire revocation story for dnstt -- generates the host
# key into the volume, writes /etc/ssh/sshd_config, and then sshd needs root to
# set*id into each session's own account. See compose.yml for what it is
# allowed to keep and what was taken away.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
