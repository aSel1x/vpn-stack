# The SSH front for the DNS tunnel, in a container rather than on the host.
#
# iOS clients (HTTP Injector, AnyBridge) speak DNSTT -> SSH: they log in over
# the tunnel and forward through it. That needs an sshd and a login. Putting
# both here instead of on the host means no host account, no edit to the host's
# /etc/ssh/sshd_config, and a login whose blast radius is an empty Alpine
# container with no privileges and nothing mounted.
#
# It rides network_mode: host, so 127.0.0.1:7300 inside is the microsocks the
# dnstt-socks container binds -- same loopback, one namespace.
FROM alpine:3.20
RUN apk add --no-cache openssh-server openssh-sftp-server tini
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
