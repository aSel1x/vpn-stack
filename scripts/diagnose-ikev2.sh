#!/bin/bash
# Read-only IKEv2 reachability diagnostic. Changes nothing, starts nothing,
# writes nothing outside /tmp. Safe to run on the live server.
#
# WHY THIS EXISTS
# ---------------
# Clients establish nothing because their IKE never reaches this host. Three
# configurations were already ruled out (privileged container, non-privileged
# container, full bare-metal hwdsl2 install), which eliminates everything *on*
# the box. What is left are three hypotheses that look identical from the
# server and need completely different responses:
#
#   (A) inbound UDP 500/4500 is dropped BEFORE this host -- hosting provider's
#       edge firewall / security group. Fix: open it in the provider panel.
#   (B) outbound UDP 500/4500 is dropped at the CLIENT's network -- some mobile
#       carriers and corporate NATs block those ports outright.
#   (C) UDP 500/4500 flows fine, but something on the path classifies the
#       ISAKMP payload and drops only well-formed IKE. Ports are open, junk
#       traverses happily, and every real client still fails.
#
# (C) is not hypothetical: it is what was actually happening here, measured
# 2026-09-08. And it is invisible to the obvious test. THIS SCRIPT USED TO SEND
# A PLAIN 'DIAGPROBE-<host>' DATAGRAM, which is exactly the shape such a filter
# lets through -- so it reported "the probe arrived, the provider is fine" and
# blamed the client, which was directionally right for the wrong reason and
# would have been flatly wrong against a provider that really did block (A).
#
# A junk datagram on port 500 is not a proxy for IKE. Only a genuine
# IKE_SA_INIT answers the question, so `probe` now sends one, plus a junk
# control with a different marker so `listen` can report WHICH shape arrived.
#
# `path` is the strongest test and needs no second host at all: it walks TTLs
# with both shapes. A probe that expires mid-path cannot have reached the
# destination, so if IKE stops earning ICMP time-exceeded at a hop where junk
# still earns it, the filter is at that hop -- upstream of the destination,
# whoever owns it. That is what identified the real culprit here.
#
# USAGE
#   From the FAILING client's own network, first -- it needs nothing else:
#                          bash scripts/diagnose-ikev2.sh probe <server-ip>
#                          bash scripts/diagnose-ikev2.sh path  <server-ip>
#
#   On the VPN server:     sudo bash scripts/diagnose-ikev2.sh listen
#   Then, from the client: bash scripts/diagnose-ikev2.sh probe <server-ip>
#   A probe from some OTHER network exonerates only that other network.
#
#   Local state only:      bash scripts/diagnose-ikev2.sh local
#
# Run `listen` first and leave it running; it captures for 90s by default.
#
# EXIT STATUS, one convention across all four modes and the Python tool:
#   0  measured, and healthy
#   1  measured, and a defect was found
#   2  NOT MEASURED -- the datagram never left this host, the capture never
#      ran, the name did not resolve, iptables was unreadable. Distinct from 1
#      deliberately: this entire script exists because a verdict read off a
#      measurement that did not happen is how the original diagnosis went
#      wrong, and a wrapper that reads "could not look" as "nothing wrong"
#      repeats that mistake one level up. Refusing to run for want of root is
#      in this class too, not in the class below.
# A bad invocation -- no mode, no target -- exits 1 without measuring anything;
# it is a usage error and never a verdict about a server.

# No -e, on purpose. Every check here is a question whose answer may well be a
# failing command -- `iptables -C` on a missing rule, `docker inspect` on an
# absent container, `grep -q` on output that does not match -- and aborting on
# the first one would survey the box down to that line and say nothing about
# the rest, which is the opposite of what a diagnostic is for.
set -uo pipefail

MODE="${1:-}"
CONTAINER_UP=0
HAVE_DOCKER=0
# What `listen` and `local` exit with. c_bad is the single funnel for "measured
# and broken"; INCONCLUSIVE is set wherever a check could not run at all.
FAILED=0
INCONCLUSIVE=0
CAPTURE_SECONDS="${CAPTURE_SECONDS:-90}"
IKEV2_PORTS="500 4500 1701"

c_head() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
c_ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
c_bad()  { FAILED=1; printf '  \033[31m✗\033[0m %s\n' "$1"; }
c_warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
c_info() { printf '    %s\n' "$1"; }

IKE_TOOL=""
cleanup_ike_tool() { [[ -n "$IKE_TOOL" ]] && rm -f "$IKE_TOOL"; }
trap cleanup_ike_tool EXIT

# The probe payloads live in Python because a genuine IKE_SA_INIT cannot be
# built with printf and /dev/udp -- and a packet that is not genuine is the
# very mistake this script used to make. Written to a temp file so the script
# stays a single portable file you can scp to any box.
write_ike_tool() {
  if ! command -v python3 >/dev/null; then
    c_bad "python3 not found -- cannot build a genuine IKE packet"
    c_info "without it this script can only send junk, which CANNOT distinguish"
    c_info "hypothesis (C) from a healthy path. Install python3 and re-run."
    return 1
  fi
  IKE_TOOL=$(mktemp /tmp/ikev2-diag-tool-XXXXXX.py) || return 1
  cat > "$IKE_TOOL" <<'IKETOOL_EOF'
#!/usr/bin/env python3
"""IKE-shaped probes for diagnose-ikev2.sh.

Sends packets and reads replies. Opens no SA, authenticates nothing, writes
nothing. The half-open SAs it leaves on a real responder age out on their own.

Why this exists at all: a junk UDP datagram on port 500 is NOT a proxy for
IKE. A path can pass arbitrary UDP to 500/4500 all day and still destroy every
well-formed ISAKMP packet, which is exactly what was measured on 2026-09-08.
Only a genuine IKE_SA_INIT can tell you whether IKE gets through.
"""
import os
import socket
import struct
import sys
import time

IP_RECVERR = 11
EXCH_SA_INIT = 34
PL_SA, PL_KE, PL_NONCE, PL_NOTIFY = 33, 34, 40, 41
PL_NAMES = {0: "NONE", 33: "SA", 34: "KE", 38: "CERTREQ", 40: "Nonce", 41: "Notify", 43: "VendorID"}

MODP2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)


def _transform(last, ttype, tid, keylen=None):
    attrs = struct.pack("!HH", 0x800E, keylen) if keylen is not None else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def _proposal(num, transforms, last):
    body = b"".join(transforms)
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, 8 + len(body), num, 1, 0, len(transforms)) + body


def _payload(nxt, body):
    return struct.pack("!BBH", nxt, 0, 4 + len(body)) + body


def sa_init(marker: bytes):
    """A genuine, standards-shaped IKEv2 IKE_SA_INIT request.

    The marker rides in the nonce, which is 32 opaque bytes to any responder,
    so the packet stays valid while `listen` can still grep it out of a capture.
    """
    spi_i = os.urandom(8)
    proposals = (
        _proposal(1, [_transform(False, 1, 12, 256), _transform(False, 2, 5),
                      _transform(False, 3, 12), _transform(True, 4, 14)], last=False)
        + _proposal(2, [_transform(False, 1, 20, 256), _transform(False, 2, 5),
                        _transform(True, 4, 14)], last=True)
    )
    sa = _payload(PL_KE, proposals)
    ke_data = pow(2, int.from_bytes(os.urandom(32), "big"), MODP2048).to_bytes(256, "big")
    ke = _payload(PL_NONCE, struct.pack("!HH", 14, 0) + ke_data)
    nonce_body = (marker + os.urandom(32))[:32]
    nonce = _payload(PL_NOTIFY, nonce_body)
    notify = _payload(0, struct.pack("!BBH", 0, 0, 16406))  # IKEV2_FRAGMENTATION_SUPPORTED
    body = sa + ke + nonce + notify
    header = struct.pack("!8s8sBBBBII", spi_i, b"\x00" * 8, PL_SA, 0x20,
                         EXCH_SA_INIT, 0x08, 0, 28 + len(body))
    return spi_i, header + body


def junk(marker: bytes, size: int) -> bytes:
    return (marker + b"-" + os.urandom(max(0, size - len(marker) - 1)))[:size]


def describe(data: bytes) -> str:
    if len(data) < 28:
        return "runt (%d bytes)" % len(data)
    _, spi_r, nxt, ver, exch, flags, _, _ = struct.unpack("!8s8sBBBBII", data[:28])
    names, off, n = [], 28, nxt
    while n and off + 4 <= len(data):
        pn, _, plen = struct.unpack("!BBH", data[off:off + 4])
        if plen < 4:
            break
        names.append(PL_NAMES.get(n, str(n)))
        n, off = pn, off + plen
    return "exch=%d ver=0x%02x flags=0x%02x spi_r=%s payloads=%s" % (
        exch, ver, flags, spi_r.hex(), "/".join(names) or "-")


RESOLVED = {}


def resolve(host, port):
    """Resolve once, up front. A name that does not resolve is its own answer,
    and must never be reported as "no reply" -- that reads as filtering."""
    key = (host, port)
    if key not in RESOLVED:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        RESOLVED[key] = (infos[0][0], infos[0][4])
    return RESOLVED[key]


def _sock(host, port=500, ttl=None, recverr=False):
    family, _ = resolve(host, port)
    s = socket.socket(family, socket.SOCK_DGRAM)
    if ttl is not None:
        if family == socket.AF_INET:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        else:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    if recverr and family == socket.AF_INET:
        s.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
    return s


def send_and_wait(host, port, payload, wait=3.0, expect_spi=None):
    """Send one datagram on a fresh 5-tuple.

    Returns ("reply", data) | ("noreply", None) | ("nosend", errtext).
    The three are deliberately distinct: a datagram that never left this host
    proves nothing, and reporting it as "no reply" is exactly how a broken
    probe manufactures a confident filtering verdict.

    connect() before send so the kernel drops anything not from the peer, and
    when expect_spi is given the reply must carry that initiator SPI and be an
    IKE_SA_INIT response -- otherwise a stray scan datagram landing on our
    ephemeral port counts as the server answering.
    """
    _, sockaddr = resolve(host, port)
    s = _sock(host, port)
    s.settimeout(wait)
    wire = b"\x00\x00\x00\x00" + payload if port == 4500 else payload
    try:
        s.connect(sockaddr)
        s.send(wire)
    except OSError as e:
        s.close()
        return "nosend", "%s (errno %s)" % (e.strerror or e, getattr(e, "errno", "?"))
    deadline = time.time() + wait
    try:
        while time.time() < deadline:
            s.settimeout(max(0.05, deadline - time.time()))
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if port == 4500 and data[:4] == b"\x00\x00\x00\x00":
                data = data[4:]
            if expect_spi is not None:
                if len(data) < 28 or data[:8] != expect_spi:
                    continue
                if data[18] != EXCH_SA_INIT:
                    continue
            return "reply", data
    finally:
        s.close()
    return "noreply", None


SO_EE_ORIGIN_ICMP = 2
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACH = 3
ICMP_PORT_UNREACH = 3  # code, within type 3


def hop_at_ttl(host, port, payload, ttl, dest=None, wait=2.0):
    """Return (ip, kind) for the ICMP error our probe drew, else (None, None).

    kind is one of:
      "ttl"    time-exceeded -- the probe expired there, so that router did
               forward it that far;
      "closed" port-unreachable from the DESTINATION -- the probe arrived
               complete and nothing was listening. That is positive proof of
               reachability and the opposite of a filtering result;
      "reject" any other destination-unreachable, i.e. administratively
               prohibited and friends. A filter announcing itself, and it must
               NOT be read as "IKE travelled this far", which would exonerate
               the very box doing the dropping.

    The closed/reject split is not cosmetic. Both arrive as ICMP type 3, and
    lumping them together made a server whose ikev2 container was simply down
    report "IKE was actively REJECTED at hop N ... it sits upstream of the
    destination, so nothing on the server can change it" -- pointing at a
    middlebox on the evidence that the destination itself answered.
    Only SO_EE_ORIGIN_ICMP is accepted; a local error is not a hop.
    """
    _, sockaddr = resolve(host, port)
    s = _sock(host, port, ttl=ttl, recverr=True)
    s.settimeout(0.1)
    try:
        s.connect(sockaddr)
        s.send(payload)
    except OSError:
        s.close()
        return None, None
    deadline = time.time() + wait
    try:
        while time.time() < deadline:
            try:
                _, anc, _, _ = s.recvmsg(0, 1024, socket.MSG_ERRQUEUE)
            except OSError:
                time.sleep(0.05)
                continue
            for lvl, typ, cdata in anc:
                if lvl != socket.IPPROTO_IP or typ != IP_RECVERR or len(cdata) < 24:
                    continue
                _, origin, ic_type, ic_code = struct.unpack_from("=IBBB", cdata, 0)
                if origin != SO_EE_ORIGIN_ICMP:
                    continue
                ip = socket.inet_ntoa(cdata[20:24])
                if ic_type == ICMP_TIME_EXCEEDED:
                    return ip, "ttl"
                if ic_type == ICMP_DEST_UNREACH:
                    if ic_code == ICMP_PORT_UNREACH and ip == dest:
                        return ip, "closed"
                    return ip, "reject"
                return ip, "other"
    finally:
        s.close()
    return None, None


def cmd_probe(host, ike_tag, junk_tag):
    try:
        resolve(host, 500)
    except OSError as e:
        print("  \033[31m\u2717\033[0m cannot resolve %s: %s" % (host, e))
        return 2

    ike_reply = 0
    unsent = 0
    print("    Sending a GENUINE IKE_SA_INIT and a same-size junk control to each port.")
    print("    They carry DIFFERENT markers (%s / %s) so `listen` on the server can"
          % (ike_tag.decode(), junk_tag.decode()))
    print("    say which shape arrived -- that distinction is the whole point.\n")
    # The genuine packet goes FIRST on every port, and each shape gets its own
    # 5-tuple. The filter measured on 2026-09-08 is stateful and decides on the
    # first datagram of a flow: priming a tuple with junk and then sending the
    # byte-identical IKE_SA_INIT down it got the IKE through and pluto answered
    # in full. Send the control first, or share one socket between the two, and
    # this probe reports a healthy path on the exact network where every real
    # client fails -- a real client's first packet IS its IKE_SA_INIT.
    for port in (500, 4500):
        spi, pkt = sa_init(ike_tag)
        status, data = send_and_wait(host, port, pkt, expect_spi=spi)
        if status == "reply":
            ike_reply += 1
            print("  \033[32m\u2713\033[0m udp/%-4d genuine IKE_SA_INIT (%d B) -> REPLY %d B: %s"
                  % (port, len(pkt), len(data), describe(data)))
        elif status == "nosend":
            unsent += 1
            print("  \033[31m\u2717\033[0m udp/%-4d genuine IKE_SA_INIT COULD NOT BE SENT: %s"
                  % (port, data))
        else:
            print("  \033[31m\u2717\033[0m udp/%-4d genuine IKE_SA_INIT (%d B) -> no reply"
                  % (port, len(pkt)))

        ctrl = junk(junk_tag, len(pkt))
        cstatus, cdata = send_and_wait(host, port, ctrl, wait=1.0)
        if cstatus == "nosend":
            unsent += 1
            print("      udp/%-4d junk control COULD NOT BE SENT: %s" % (port, cdata))
        else:
            print("      udp/%-4d junk control (%d B) sent (a responder ignores it; for `listen`)"
                  % (port, len(ctrl)))
        time.sleep(0.3)

    print()
    # A reply is positive proof and is read before `unsent`, which is only ever
    # "something could not be measured". The junk control exists to give
    # `listen` something to compare against; failing to send it cannot unprove
    # an answer that already came back.
    if ike_reply:
        if unsent:
            print("  \033[33m!\033[0m %d datagram(s) never left this host; the IKE reply above stands anyway."
                  % unsent)
        print("  \033[32m\u2713\033[0m IKE works end to end BETWEEN THIS HOST AND %s." % host)
        print("    That exonerates this path only. If the failing client is on a different")
        print("    network, re-run this from that network -- this result says nothing about it.")
        return 0
    if unsent:
        print("  \033[31m\u2717\033[0m %d datagram(s) never left this host -- this says nothing about the" % unsent)
        print("    path or the server. Fix the local firewall/routing and re-run.")
        return 2
    me = os.environ.get("DIAG_SCRIPT", "scripts/diagnose-ikev2.sh")
    print("  \033[31m\u2717\033[0m No IKE reply. Now find out where it dies:")
    print("      bash %s path %s      # does IKE die mid-path while junk survives?" % (me, host))
    print("      sudo bash %s listen    # on the server: does either shape arrive?" % me)
    return 1


def cmd_path(host, ike_tag, junk_tag, max_ttl=20):
    try:
        family, sockaddr = resolve(host, 500)
    except OSError as e:
        print("  cannot resolve %s: %s" % (host, e))
        return 2
    # IPv4-only, decided on the RESOLVED family rather than on a ':' in the
    # argument: hop_at_ttl reads ICMP off the IPv4 error queue only, so a name
    # with nothing but an AAAA record passed that test, drew no ICMP at all, and
    # printed twenty empty hops -- a walk that never happened, presented as one
    # that found nothing.
    if family != socket.AF_INET:
        print("  path mode is IPv4-only (it needs IP_RECVERR); use `probe` for IPv6.")
        return 2
    # Every comparison below is against the resolved address, never the string
    # the operator typed: the early exit "we have reached the destination" can
    # never fire for a hostname, so a named target walked all 20 TTLs and the
    # trailing hops read as a path that stopped answering.
    dest = sockaddr[0]
    if dest != host:
        print("    %s resolves to %s; every hop below is on the way there.\n" % (host, dest))

    print("    Walking TTLs with a genuine IKE_SA_INIT and with junk of the SAME size,")
    print("    interleaved so path conditions are identical. A probe that expires mid-path")
    print("    cannot have reached the destination -- so if IKE stops earning ICMP replies")
    print("    at a hop where junk still does, that hop is the filter, and it is upstream")
    print("    of the destination no matter who owns the address.")
    print("    '!' is an ICMP administrative reject -- a filter announcing itself.")
    print("    '?' is an ICMP port-unreachable from the destination: the probe ARRIVED")
    print("        and nothing was listening, which is proof of reach, not of filtering.\n")
    print("    %-5s %-24s %-24s" % ("ttl", "genuine IKE_SA_INIT", "junk control"))
    print("    " + "-" * 56)

    ike_last = junk_last = 0
    ike_hops = junk_hops = 0
    ike_reject = ike_closed = None
    marks = {"reject": "!", "closed": "?"}
    for ttl in range(1, max_ttl + 1):
        spi, pkt = sa_init(ike_tag)
        a, akind = hop_at_ttl(host, 500, pkt, ttl, dest=dest)
        b, bkind = hop_at_ttl(host, 500, junk(junk_tag, len(pkt)), ttl, dest=dest)
        if a:
            ike_hops += 1
            if akind == "ttl":
                ike_last = ttl
            elif akind == "closed" and ike_closed is None:
                ike_closed = (ttl, a)
            elif akind == "reject" and ike_reject is None:
                ike_reject = (ttl, a)
        if b:
            junk_hops += 1
            if bkind == "ttl":
                junk_last = ttl
        fmt = lambda ip, k: "-" if not ip else (ip + marks.get(k, ""))
        print("    %-5d %-24s %-24s" % (ttl, fmt(a, akind), fmt(b, bkind)))
        # A reject does not end the walk: the point of the remaining TTLs is to
        # show whether junk keeps going past the device that refused us.
        if a and a == dest and akind != "reject":
            break

    # Does IKE reach the destination at all? A reply is the only positive proof,
    # and it is what separates "no filtering" from "we simply learned nothing".
    spi, pkt = sa_init(ike_tag)
    status, _ = send_and_wait(host, 500, pkt, expect_spi=spi)
    reached = status == "reply"

    print()
    if status == "nosend":
        print("  Inconclusive: this host could not send the probe at all.")
        return 2
    if reached:
        print("  \033[32m\u2713\033[0m A genuine IKE_SA_INIT reached %s and was answered." % dest)
        print("    Nothing on this path is filtering IKE.")
        return 0
    if ike_closed:
        ttl_c, _ = ike_closed
        print("  \033[31m\u2717\033[0m A genuine IKE_SA_INIT REACHED %s (hop %d answered ICMP port"
              % (dest, ttl_c))
        print("    unreachable), so nothing on this path filters IKE -- but nothing is")
        print("    listening on udp/500 there either. That is a server-side fault, not a")
        print("    path one: run `listen` and `local` on the destination.")
        return 1
    if ike_reject:
        ttl_r, ip_r = ike_reject
        print("  \033[31m\u2717\033[0m IKE was actively REJECTED by %s at hop %d (ICMP prohibited)."
              % (ip_r, ttl_r))
        print("    That device refused the packet rather than forwarding it. It sits upstream")
        print("    of the destination, so nothing on the server can change it.")
        print("    Re-run this toward a host you know answers IKE: if that one survives the")
        print("    same hop, the filter is keyed on destination.")
        return 1
    if junk_hops < 2:
        print("  Inconclusive: only %d hop(s) answered ICMP at all, for either shape." % junk_hops)
        print("    Many networks suppress ICMP entirely; this walk cannot see through that.")
        print("    Use `probe` from the failing client's network, and `listen` on the server.")
        return 2
    if junk_last > ike_last:
        suspect = ike_last + 1
        if ike_last == 0:
            print("  \033[31m\u2717\033[0m IKE earned no ICMP reply at ANY ttl; junk reached hop %d." % junk_last)
            print("    => it is being dropped at or before the first hop that answers.")
        else:
            print("  \033[31m\u2717\033[0m IKE stops after hop %d; junk keeps going to hop %d."
                  % (ike_last, junk_last))
        print("    => a device at/just before hop %d is classifying the ISAKMP payload and" % suspect)
        print("       dropping it. It sits UPSTREAM of the destination, so nothing on the")
        print("       server can fix it. Re-run this toward a host you know answers IKE: if")
        print("       that one survives the same hop, the filter is keyed on destination.")
        return 1
    print("  IKE and junk travel equally far (hop %d vs %d), but no IKE reply came back."
          % (ike_last, junk_last))
    print("    No content-based filtering is visible on this path. Look at the destination")
    print("    itself: run `listen` there and check whether pluto is bound and answering.")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("probe", "path"):
        print("usage: %s probe|path <host>" % sys.argv[0], file=sys.stderr)
        sys.exit(2)
    mode, target = sys.argv[1], sys.argv[2]
    host_tag = socket.gethostname()[:14]
    ike_tag = ("DIAGIKE-%s" % host_tag).encode()
    junk_tag = ("DIAGJUNK-%s" % host_tag).encode()
    sys.exit(cmd_probe(target, ike_tag, junk_tag) if mode == "probe"
             else cmd_path(target, ike_tag, junk_tag))
IKETOOL_EOF
  return 0
}

# Which kind of address a udp port is served on: "wildcard <addr>", "public
# <addr>", "loopback", or "absent". Parses the address column the way
# composectl._is_bound and smoke.sh's loopback_bind do, and asks ss for the port
# with `sport = :N` instead of grepping its output for the number: hwdsl2's own
# IPv6 pool is fddd:500:500:500::/64, so a grep for ":500\b" over `ss -lunp`
# matches a socket bound to that address on some completely different port and
# announces udp/500 as served when charon never bound it. Exactly the substring
# trap that reported dnstt's 53/udp as served on every stock Ubuntu, where
# systemd-resolved holds 127.0.0.53:53.
#
# The wildcard case is separate because it is the one this got wrong: a socket
# on 0.0.0.0:500 (or *:500 on older ss) serves every global address, and
# demanding a literal address out of `ip addr` reported it as "bound, but NOT on
# any global address (loopback only)" -- a healthy box called broken, the same
# failure shape as the hardcoded pool below.
udp_bind() {
  ss -H -lun "sport = :$1" 2>/dev/null | awk '
    { a = $4; sub(/:[0-9]+$/, "", a); sub(/%.*/, "", a)
      if (a == "0.0.0.0" || a == "*" || a == "[::]" || a == "::") { if (wild == "") wild = a }
      else if (a ~ /^127\./ || a == "[::1]" || a == "::1") lo = 1
      else pub = a }
    END { if (wild != "")     print "wildcard " wild
          else if (pub != "") print "public " pub
          else if (lo)        print "loopback"
          else                print "absent" }'
}

# Is this a real network, and what is its canonical form? This was a regex, and
# a regex is shape-only: "192.168.256.0/24" matches ^[0-9]+(\.[0-9]+){3}/[0-9]+$
# perfectly, is not an address, and makes `iptables -C` fail in a way
# indistinguishable from "the rule is missing" -- so the validation whose whole
# purpose is to stop a healthy box being reported as broken was the thing
# reporting it. python3 is already a hard dependency here (`probe` and `path`
# cannot build a genuine IKE_SA_INIT without it) and ipaddress is what
# vpnctl.ikev2ctl uses, so this accepts and normalises exactly the values the
# Python side does, host bits included: 192.168.43.10/24 -> 192.168.43.0/24.
valid_net() {
  [[ -n "$1" ]] || return 1
  python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False))' \
    "$1" 2>/dev/null
}

# The smallest network holding one `first-last` pool entry, which is the form
# `rightaddresspool` states it in. Line for line what vpnctl.ikev2ctl._covering_net
# does, because a value that reaches `iptables` from two implementations has to be
# the same value: derived from BOTH ends rather than assuming a /24 on the first,
# since 192.168.43.10-192.168.44.250 straddles two and calling it 192.168.43.0/24
# leaves every client above the boundary outside every rule AND outside this very
# check -- green, forwarding nothing. Wider than the pool is the safe direction:
# an address inside the covering network but outside the pool is one pluto never
# assigns. A bare CIDR is accepted too; rightaddresspool takes one.
covering_net() {
  [[ -n "$1" ]] || return 1
  python3 -c '
import ipaddress, sys
bounds = [b.strip() for b in sys.argv[1].split("-") if b.strip()]
if not bounds:
    raise SystemExit(1)
try:
    if len(bounds) == 1 and "/" in bounds[0]:
        block = ipaddress.ip_network(bounds[0], strict=False)
        first, last = block.network_address, block.broadcast_address
    else:
        first = ipaddress.ip_address(bounds[0])
        last = ipaddress.ip_address(bounds[-1])
except ValueError:
    raise SystemExit(1)
if first.version != 4 or last.version != 4 or last < first:
    raise SystemExit(1)
covering = next(ipaddress.summarize_address_range(first, last))
while covering.broadcast_address < last:
    covering = covering.supernet()
print(covering)
' "$1" 2>/dev/null
}

# The pool IKEv2 clients are actually assigned from, asked of the container
# rather than hardcoded. Mirrors vpnctl.ikev2ctl._ikev2_ipv4_net and smoke.sh's
# copy of it: `conn ikev2-cp`'s rightaddresspool is authoritative (it is what
# pluto hands out); VPN_XAUTH_NET is only a fallback, because run.sh uses the
# net for the firewall rules *it* writes while ikev2.sh builds the pool from
# XAUTH_POOL, so preferring the net would reproduce the very bug this replaced
# for anyone who set only one of the two. Both are validated before use.
#
# Byte-identical to smoke.sh's copy, and pinned there by a test that extracts
# both and runs them over the same probe set against the Python one. The two
# drifted on the fix for this very function -- this file grew the python3 guard
# and the whitespace-tolerant entry match, smoke.sh did not -- and nothing was
# watching, which is how three copies that silently disagree happen twice.
#
# Emits "net|provenance": a value that came from the hardcoded default must not
# read as a real answer, and the provenance names WHY the fallback was reached,
# so "image default, container unreadable" is distinguishable from a container
# that answered with something unusable.
ikev2_pool() {
  local line entry v net why="container unreadable"
  # Without python3 nothing below can be validated, and an unvalidated value is
  # what makes `iptables -C` fail as though the rule were missing. Say so in the
  # provenance rather than blaming the container for a tool that is absent.
  if ! command -v python3 >/dev/null; then
    printf '192.168.43.0/24|image default, python3 absent so nothing could be validated'
    return
  fi
  line=$(docker exec ipsec-vpn-server \
           sed -n 's/^[[:space:]]*rightaddresspool=//p' /etc/ipsec.d/ikev2.conf 2>/dev/null | head -1)
  if [[ -n "$line" ]]; then
    # First IPv4 entry of a comma-separated list that also carries the image's
    # IPv6 range, with any padding around it dropped -- ipsec.conf tolerates
    # whitespace after the '=' and around each entry, and python3 below will
    # refuse anything that survives this and is still not an address.
    entry=$(printf '%s' "$line" | tr ',' '\n' | grep -m1 -E '^[[:space:]]*[0-9]+(\.[0-9]+){3}' || true)
    entry=${entry//[[:space:]]/}
    net=$(covering_net "$entry") && {
      printf '%s|conn ikev2-cp rightaddresspool' "$net"; return; }
    why="conn ikev2-cp gave an unusable pool"
  fi
  v=$(docker exec ipsec-vpn-server printenv VPN_XAUTH_NET 2>/dev/null | tr -d '\r' | head -1)
  if [[ -n "$v" ]]; then
    net=$(valid_net "$v") && { printf '%s|VPN_XAUTH_NET' "$net"; return; }
    why="VPN_XAUTH_NET=$v does not parse as a network"
  fi
  printf '192.168.43.0/24|image default, %s' "$why"
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    # 2: nothing was measured. A caller that reads this as 1 would record a
    # finding about the server from a run that never looked at it.
    echo "This mode needs root (tcpdump, iptables, ss -p). Re-run with sudo." >&2
    exit 2
  fi
}

# ---------------------------------------------------------------- local state

check_local() {
  c_head "Container"
  # A missing docker is a reason to skip the container questions, not to abandon
  # the survey: the listeners, ufw, INPUT, FORWARD and sysctl checks all read the
  # host, and one of the three configurations already ruled out here was a
  # bare-metal hwdsl2 install with no container at all. Returning here printed a
  # single line and exited 0 on a box nobody had looked at.
  local state
  CONTAINER_UP=0
  HAVE_DOCKER=0
  if ! command -v docker >/dev/null; then
    c_warn "docker not found -- no container to inspect (bare-metal install, or the wrong host)"
    INCONCLUSIVE=1
  else
    HAVE_DOCKER=1
    state=$(docker inspect -f '{{.State.Status}}' ipsec-vpn-server 2>/dev/null | tr -d '\n')
    if [[ "$state" == "running" ]]; then
      CONTAINER_UP=1
      c_ok "ipsec-vpn-server is running"
    elif [[ -z "$state" ]]; then
      c_bad "no ipsec-vpn-server container exists on this host"
      c_info "if you meant to run this on the VPN server, you are on the wrong host"
    else
      c_bad "ipsec-vpn-server is '$state' -- nothing can arrive at a stopped container"
      c_info "start it: docker compose up -d ikev2"
    fi
  fi

  c_head "Listeners"
  # network_mode: host, so the sockets belong to the container's charon/pluto
  # but appear in the host's namespace.
  local p verdict
  # Every verdict below is udp_bind's, and udp_bind's only source is ss. Without
  # it each port reads as "no listener" -- a finding about the server drawn from
  # a tool that was never there.
  if ! command -v ss >/dev/null; then
    c_warn "ss not found (iproute2) -- the listener checks cannot run at all"
    INCONCLUSIVE=1
  fi
  for p in 500 4500; do
    verdict=$(udp_bind "$p")
    case "$verdict" in
      wildcard\ *|public\ *)
        c_ok "udp/$p is bound on a globally reachable address (${verdict#* })" ;;
      loopback)
        c_bad "udp/$p is bound on loopback only -- it can never answer a real client" ;;
      *)
        if (( CONTAINER_UP )); then
          c_bad "udp/$p has NO listener -- the container runs but charon did not bind"
        else
          c_bad "udp/$p has no listener (expected: the container is not running)"
        fi ;;
    esac
    # -H: without it ss prints its column header even when the filter matched
    # nothing, so an absent listener was followed by a line that looked like
    # output about a socket.
    ss -H -lunp "sport = :$p" 2>/dev/null | tr -s ' ' | sed 's/^/      /'
  done
  case "$(udp_bind 1701)" in
    absent)
      c_warn "udp/1701 has no listener -- L2TP will not work (IKEv2 does not need it)" ;;
    loopback)
      c_warn "udp/1701 is bound on loopback only -- L2TP will not work (IKEv2 does not need it)" ;;
    *)
      c_ok "udp/1701 is bound (L2TP)" ;;
  esac

  c_head "Host firewall"
  # `ufw status` needs root and says so on stderr, exiting nonzero. Folded into
  # one condition with the active test, that read as "inactive or absent" for a
  # ufw that is running and simply was not readable -- the third possibility,
  # reported as the harmless one, in the mode documented as runnable without sudo.
  if ! command -v ufw >/dev/null; then
    c_warn "ufw absent -- not the blocker, but check iptables below"
  elif ! ufw status >/dev/null 2>&1; then
    c_warn "ufw is installed but its status needs root -- NOT read. Re-run with sudo."
    INCONCLUSIVE=1
  elif ufw status | grep -q '^Status: active'; then
    for p in $IKEV2_PORTS; do
      if ufw status | grep -qE "^$p/udp\s+ALLOW"; then
        c_ok "ufw allows $p/udp"
      else
        c_bad "ufw does NOT allow $p/udp"
        c_info "fix: ufw allow $p/udp"
      fi
    done
  else
    c_warn "ufw inactive -- not the blocker, but check iptables below"
  fi

  c_head "iptables INPUT (would a packet that arrives be accepted?)"
  local pol
  pol=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/{print $3}')
  if [[ -z "$pol" ]]; then
    # Names every check this skips, and exits 2 rather than 0. Not performing
    # the FORWARD check is not a pass: it is the one documented failure where
    # the SA comes up and no traffic moves, and a survey that silently stopped
    # short of it while returning success is the shape of mistake this whole
    # script is a correction for.
    c_warn "cannot read iptables (needs root) -- skipping the INPUT, FORWARD,"
    c_info "sysctl and strongSwan checks. Re-run with sudo: the FORWARD pair is"
    c_info "the documented silent-no-traffic failure and has not been looked at."
    INCONCLUSIVE=1
    return
  fi
  c_info "INPUT policy: $pol"
  # Match across the WHOLE ruleset, not just the INPUT chain: INPUT jumps into
  # ufw-* sub-chains, and ports are often expressed as `-m multiport --dports`.
  local all_rules
  all_rules=$(iptables -S 2>/dev/null)
  for p in 500 4500; do
    if grep -qE -- "(--dport $p|--dports [0-9,]*\b$p\b)[^!]*-j ACCEPT" <<<"$all_rules"; then
      c_ok "an ACCEPT rule covers dport $p"
      grep -E -- "(--dport $p|--dports [0-9,]*\b$p\b).*ACCEPT" <<<"$all_rules" | sed 's/^/      /'
    elif [[ "$pol" == "ACCEPT" ]]; then
      c_ok "no explicit rule, but INPUT policy is ACCEPT"
    else
      c_bad "no ACCEPT anywhere for dport $p and INPUT policy is $pol"
    fi
  done

  c_head "IKEv2 IPv4 FORWARD rules (the documented silent-no-traffic failure)"
  local iface
  iface=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
  c_info "default interface: ${iface:-unknown}"
  if [[ -n "${iface:-}" ]]; then
    # This checked 192.168.42.0/24 until 2026-09-08 -- the L2TP pool. IKEv2
    # clients are handed addresses from XAUTH_NET (.43 by default), so the
    # check passed on a box where the rules that matter were absent. Ask the
    # container which pool it actually hands out.
    local poolinfo net netsrc a=0 b=0
    poolinfo=$(ikev2_pool); net=${poolinfo%%|*}; netsrc=${poolinfo#*|}
    c_info "IKEv2 client pool: $net  ($netsrc)"
    iptables -C FORWARD -i "$iface" -d "$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && a=1
    iptables -C FORWARD -s "$net" -o "$iface" -j ACCEPT 2>/dev/null && b=1
    if (( a && b )); then
      c_ok "both FORWARD accepts for $net are present"
    else
      c_bad "FORWARD accepts MISSING for $net (inbound=$a outbound=$b)"
      c_info "this alone makes clients connect and carry no traffic"
      c_info "fix: vpnctl apply  (ikev2ctl.ensure_ipv4_forwarding re-inserts them)"
    fi
  else
    # ikev2ctl.ensure_ipv4_forwarding fails with the same complaint, and for the
    # same reason: the rules are written against the default interface, so
    # without one there is no rule to look for and nothing routes anyway.
    c_bad "no default route -- cannot name the interface the FORWARD pair is written against"
  fi

  c_head "Sysctls"
  for s in net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects; do
    c_info "$s = $(sysctl -n "$s" 2>/dev/null || echo '?')"
  done
  if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" != "1" ]]; then
    c_bad "ip_forward is off -- nothing routes"
  fi

  c_head "strongSwan's own view"
  # Captured, then printed: `docker exec ... | head -20` under pipefail reports
  # the pipeline as failed when head closes the pipe early, so a container that
  # answered perfectly drew "could not query ipsec status".
  local ipsecout=""
  (( HAVE_DOCKER )) && ipsecout=$(docker exec ipsec-vpn-server ipsec status 2>/dev/null | head -20)
  if [[ -n "$ipsecout" ]]; then
    printf '%s\n' "$ipsecout" | sed 's/^/    /'
  elif (( HAVE_DOCKER )); then
    c_warn "could not query ipsec status inside the container"
  else
    c_warn "no docker on this host -- cannot ask strongSwan for its own view"
  fi
}

# --------------------------------------------------------------- listen mode

do_listen() {
  need_root
  command -v tcpdump >/dev/null || { echo "tcpdump not installed: apt install -y tcpdump" >&2; exit 1; }

  check_local

  local pub
  pub=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)

  c_head "Capturing for ${CAPTURE_SECONDS}s"
  cat <<EOF
    Listening on ALL interfaces for udp/500, udp/4500, udp/1701 and ESP.
    This host's global IPv4: ${pub:-unknown}

    While this runs, do BOTH of these:
      1. try to connect the failing IKEv2 client
      2. from the FAILING CLIENT's own network, run:
             bash scripts/diagnose-ikev2.sh probe ${pub:-<this-ip>}
         (a probe from some other network only exonerates that other network)

    Anything that reaches this host's NIC shows up below, even if a firewall
    would later drop it -- tcpdump taps before netfilter's INPUT chain.

EOF

  local out=/tmp/ikev2-diag-$$.txt err=/tmp/ikev2-diag-$$.err rc=0
  # Created 0600 before tcpdump writes into it. -A means the capture holds the
  # payload of every datagram on those ports, whoever sent it; that is a file
  # about other people's traffic and does not belong in /tmp world-readable.
  ( umask 077; : >"$out"; : >"$err" )
  # -A prints payload as ASCII: required, or the DIAGIKE / DIAGJUNK markers are
  # invisible and the verdict below cannot tell which packet SHAPE arrived --
  # which is the entire discriminator. Do not drop -A to save volume.
  timeout "$CAPTURE_SECONDS" tcpdump -nni any -A -c 200 \
    '(udp port 500 or udp port 4500 or udp port 1701 or proto 50)' 2>"$err" | tee "$out"
  rc=${PIPESTATUS[0]}

  c_head "Verdict"
  # 124 is timeout doing its job -- the capture ran the whole window. 0 means
  # tcpdump hit -c 200 first. Anything else and tcpdump never captured, and its
  # stderr went to a file instead of /dev/null precisely so this can say so: an
  # empty capture from a tcpdump that failed to start looks identical to one
  # from a path that dropped everything, and reading it as "NOTHING arrived"
  # manufactures hypothesis (A)/(B) out of a measurement that never happened.
  if (( rc != 0 && rc != 124 )); then
    # c_warn, not c_bad: "could not measure" is the ! marker everywhere in this
    # script, and it exits 2, while a ✗ claims a finding this run cannot support.
    c_warn "tcpdump did not run to completion (exit $rc) -- this capture proves NOTHING"
    [[ -s "$err" ]] && sed 's/^/      /' "$err"
    c_info "no verdict follows, deliberately: an empty capture from a tcpdump that"
    c_info "never started is not evidence about the path. Fix that and re-run."
    INCONCLUSIVE=1
    c_info ""
    c_info "raw capture kept at $out"
    return
  fi
  [[ -s "$err" ]] && sed 's/^/      /' "$err"
  local diagike diagjunk ike
  diagike=$(grep -c 'DIAGIKE' "$out" 2>/dev/null || true)
  diagjunk=$(grep -c 'DIAGJUNK' "$out" 2>/dev/null || true)
  # Every isakmp-port packet, ours included. tcpdump -A puts the payload on a
  # separate line from the header, so a marker can NOT be excluded per packet
  # here; this is a coarse "was there any IKE-port traffic at all" count and
  # must not be presented as third-party traffic.
  ike=$(grep -cE '\.(500|4500) *[:>]' "$out" 2>/dev/null || true)
  diagike=${diagike:-0}; diagjunk=${diagjunk:-0}; ike=${ike:-0}

  if (( diagike > 0 )); then
    c_ok "a GENUINE IKE_SA_INIT arrived -- nothing filters IKE on the PROBING HOST's path"
    c_info "that exonerates the network the probe came from, and nothing else."
    c_info "If the probe ran on the failing client's own network, look at this server"
    c_info "(FORWARD rules above, docker logs ipsec-vpn-server) or the client's profile."
    c_info "If it ran anywhere else, this says nothing about the client: re-run"
    c_info "  bash scripts/diagnose-ikev2.sh probe ${pub:-<this-ip>}"
    c_info "from the failing client's network. No IKE reply there and junk arriving"
    c_info "here is hypothesis (B)/(C) -- the client's own network, not this server."
  elif (( diagjunk > 0 )); then
    c_bad "the junk control arrived but the GENUINE IKE did NOT"
    c_info "=> hypothesis (C): something on the path classifies the ISAKMP payload"
    c_info "   and drops it. Ports are open; IKE specifically is not allowed through."
    c_info "   Nothing on this server can fix that. Locate the hop with:"
    c_info "       bash scripts/diagnose-ikev2.sh path ${pub:-<this-ip>}"
    c_info "   run from the SAME network as the failing client."
    c_info "   Then: use that network's working transports (VLESS/Hysteria2), or"
    c_info "   move the endpoint to a prefix the filter does not act on."
  elif (( ike > 0 )); then
    c_warn "traffic on 500/4500 arrived, but neither of our markers did"
    c_info "the probe was probably not run, or was run against a different address"
    # Nothing was measured: "my markers did not arrive" and "nothing arrived" are
    # different facts, and only the second is about filtering.
    INCONCLUSIVE=1
  else
    c_bad "NOTHING arrived at this interface at all"
    c_info "=> hypothesis (A) or (B): UDP 500/4500 is dropped outright, either at"
    c_info "   this provider's edge or on the probing host's own network."
    c_info "   Separate them by running 'probe' from a second, unrelated network."
    c_info "   (A probe that never left its own host proves nothing -- check that"
    c_info "    the probe command itself reported the packets as sent.)"
  fi
  c_info ""
  c_info "raw capture kept at $out"
}

# ---------------------------------------------------------------- probe mode

do_probe() {
  local target="${2:-}"
  [[ -n "$target" ]] || { echo "usage: $0 probe <server-ip>" >&2; exit 1; }

  c_head "Probing $target"
  # 2, not 1: no python3 and no temp file means no measurement, and a caller that
  # cannot tell that from "IKE is filtered" will act on the wrong one.
  write_ike_tool || exit 2
  DIAG_SCRIPT="$0" python3 "$IKE_TOOL" probe "$target"
  local rc=$?

  printf '\n  If you also have `listen` running on the server, read its verdict:\n'
  printf '    DIAGIKE seen               -> IKE reaches the box; look at the server or the client profile.\n'
  printf '    only DIAGJUNK seen         -> hypothesis (C): the path drops IKE by shape. Run `path`.\n'
  printf '    neither seen               -> hypothesis (A) or (B): UDP 500/4500 is blocked outright.\n\n'
  return $rc
}

# The test that needs no second host, and the one that actually found the
# answer in 2026-09. Walks TTLs with a genuine IKE_SA_INIT and with junk of the
# same size, interleaved so path conditions are identical, and reports the hop
# where the two diverge.
do_path() {
  local target="${2:-}"
  [[ -n "$target" ]] || { echo "usage: $0 path <server-ip>" >&2; exit 1; }

  c_head "Tracing where IKE dies on the way to $target"
  # 2, not 1: no python3 and no temp file means no measurement, and a caller that
  # cannot tell that from "IKE is filtered" will act on the wrong one.
  write_ike_tool || exit 2
  # The "now compare against a host you know answers IKE" follow-up is printed by
  # the two verdicts a comparison can inform, and nowhere else. Deciding it here
  # from the exit status suppressed it after a walk that never ran, correctly, but
  # still printed it when the destination itself answered ICMP port-unreachable --
  # sending the operator hunting for a middlebox in the one case where the
  # evidence says there is none and the fault is on the server.
  DIAG_SCRIPT="$0" python3 "$IKE_TOOL" path "$target"
}

case "$MODE" in
  # probe and path each report one measurement, so their own exit status IS the
  # answer and is passed straight through.
  probe)  do_probe "$@"; exit $? ;;
  path)   do_path "$@"; exit $? ;;
  listen) do_listen ;;
  local)  check_local ;;
  *)
    cat <<EOF
IKEv2 reachability diagnostic (read-only).

  bash $0 probe <server-ip>      send a REAL IKE_SA_INIT; a reply means IKE works
  bash $0 path  <server-ip>      find the hop where IKE dies but junk survives
  sudo bash $0 listen            on the VPN server; captures ${CAPTURE_SECONDS}s
  bash $0 local                  local state only, no capture

Exit status: 0 healthy, 1 a defect was measured, 2 nothing was measured (the
datagram never left, the capture never ran, iptables was unreadable). 2 is not
a pass -- read it as "look again", never as "nothing wrong".

Start with \`probe\` from the failing client's own network -- it needs no server
access and a reply settles the question outright. Separates three hypotheses:
the provider drops inbound IKE, the client's network drops outbound IKE, or
something on the path drops well-formed IKE while passing everything else.
EOF
    exit 1
    ;;
esac

# `listen` and `local` are surveys, not single measurements, so they exit with
# the worst thing the survey found: a ✗ outranks a check that could not run,
# because a defect that was actually observed is the more actionable of the two.
# Exiting 0 regardless -- which is what both modes did -- hands a wrapper, or an
# operator reading $?, a clean bill of health for a box whose FORWARD pair was
# never even looked at.
if (( FAILED )); then
  exit 1
elif (( INCONCLUSIVE )); then
  exit 2
fi
exit 0
