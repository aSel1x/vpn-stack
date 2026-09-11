# IKEv2 does not reach this server: a measurement report

**Scope.** Everything below was measured on 2026-09-08, from a single residential subscriber line
in Russia — the line's provider was Rostelecom — against one server in Sweden plus seven
third-party destinations. That is one line, one day, one vantage point. Nothing here describes that
provider's network or anybody else's subscribers; it describes what one line did. Where a claim was
not measured, this document says so rather than rounding it up into a conclusion.

## The question

IKEv2 clients on that line establish nothing. Not a failed authentication, not a proposal
mismatch — nothing. On the server, `docker logs ipsec-vpn-server` contains **zero** IKE
negotiations, ever, and `ipsec trafficstatus` is empty.

A server log with no negotiations in it reads as a server fault, or as the hosting provider
dropping inbound UDP before it arrives. Both readings are wrong here, and they cost two
expensive detours before being abandoned:

- the ikev2 container was run in **privileged mode**. It changed nothing and was reverted —
  commits *Temporarily switch ikev2 to privileged mode for diagnostics* and *Revert ikev2 to
  non-privileged mode*, findable with `git log --format='%h %s' | grep -i privileged`. The subjects
  are the citation, not the hashes: this repo's history has been rewritten, and an earlier draft of
  this very paragraph cited two hashes that no longer resolve to anything. As of writing they are
  `59ab7e4` and `7ae4c2d`;
- a **full bare-metal `hwdsl2/setup-ipsec-vpn` install** was done on the same host, outside
  Docker entirely. Also nothing.

Those two between them eliminate everything *on* the box — image, privileges, container, and
containerisation itself. Say it plainly because the next reader's instinct will be the same:
the evidence that looks most like a server problem is produced by something that never touches
the server.

What is left are the three hypotheses `scripts/diagnose-ikev2.sh` is built around. They look
identical from the server and need completely different responses:

- **(A)** inbound udp/500 and udp/4500 are dropped *before* this host — the hosting provider's
  edge. Fix: open it in the provider panel.
- **(B)** outbound udp/500 and udp/4500 are dropped at the *client's* network — some carriers
  and corporate NATs block those ports outright.
- **(C)** those ports flow fine, but something on the path classifies the ISAKMP payload and
  drops only well-formed IKE. Ports open, junk traverses happily, every real client fails.

(C) is what was happening.

## Why the obvious test is worthless

This is the transferable part of the document, and it is worth more than the conclusion.

An earlier version of `diagnose-ikev2.sh probe` sent a plain `DIAGPROBE-<host>` datagram to
udp/500 and watched for it in a capture on the server. It arrived. That arrival was read as
"the ports are open, so the provider is not blocking; blame the client".

The verdict named the right suspect on evidence that could not support it. A junk datagram
arriving proves exactly one thing: *arbitrary UDP of that size, to that port, arrives.* That
statement is strictly weaker than "IKE arrives", and the gap between them is the entire
question. Any filter keyed on payload shape — wherever it sits, the provider's edge or the
subscriber's own line — passes the control datagram and destroys every real packet. So the test
returns "not blocked" both when nothing is blocking and when IKE specifically is being
destroyed, including the case of a provider that really did block inbound IKE. A test whose
pass condition is met in the failure it exists to detect is not a weak test; it is not a test.

The general rule: **a probe must share with the real traffic every property a filter could key
on.** For IKE that means a well-formed ISAKMP header, a plausible exchange type, correct payload
chaining, and a realistic size. Junk on the right port shares one property — the port — and a
port ACL is the one hypothesis a bound-and-accepting server has already made least likely.
**A junk datagram on port 500 is not a proxy for IKE.**

Three consequences are now built into the script:

- The packet builder lives in Python inside the script, because a genuine `IKE_SA_INIT` cannot
  be produced with `printf` and `/dev/udp`. Without `python3` the script **refuses to run** and
  says why, rather than silently falling back to junk: without it "this script can only send
  junk, which CANNOT distinguish hypothesis (C) from a healthy path".
- `probe` sends both shapes, same size, with different markers — `DIAGIKE-<host>` and
  `DIAGJUNK-<host>` — so `listen` can report *which shape* arrived. The marker rides in the
  SA_INIT's nonce, which is 32 opaque bytes to any responder, so the packet stays standards-valid
  while remaining greppable in a capture.
- "no reply" and "never sent" are distinct results in the code. A datagram that never left the
  host proves nothing about the path, and reporting it as no reply is precisely how a broken
  probe manufactures a confident filtering verdict.

## The measurement that settles it

Send the probe with **TTL=3** — a ceiling of three hops set on the probe itself, shorter than the
path to any destination in the table, which is CLAUDE.md's basis for saying these probes *cannot*
have reached the addresses they were sent to. That is the property that makes this an argument
rather than a traceroute. Then vary only
the destination address; payload, size, port and source stay constant.

The table below is CLAUDE.md's record of that sweep, reproduced. **No command in this repo produces
it.** `scripts/diagnose-ikev2.sh path` walks TTL 1 through 20 against *one* destination, so a
single-TTL sweep across eight destinations is a different measurement, run by hand. The cells are
written as fractions over 3; reading that denominator as three attempts per cell, and a success as
an ICMP error arriving back from inside the ceiling, is this document's reading of the notation —
the protocol behind it is not written down anywhere.

| destination | genuine `IKE_SA_INIT` | same-size junk |
| --- | --- | --- |
| the server under test (SE) | **0/3 — dies before hop 3** | 3/3 |
| `8.8.8.8`, `1.1.1.1`, `9.9.9.9`, `185.199.108.153` | **0/3 each** | 3/3 each |
| `194.87.49.94` (Timeweb, RU-owned) | 3/3 | 3/3 |
| `77.88.8.8`, `213.180.204.242` (Yandex) | 3/3 | 3/3 |

The inference, in order:

1. Junk earned its ICMP toward every one of the eight destinations. So within those first hops,
   datagrams of that size to that port were being forwarded, and something inside the ceiling
   reported the expiry.
2. The genuine SA_INIT earned nothing toward any of the five foreign destinations — the server
   under test plus `8.8.8.8`, `1.1.1.1`, `9.9.9.9` and `185.199.108.153`. **The two shapes did not
   behave the same way, and that difference is the entire finding.** Both carried the identical
   TTL=3 ceiling, so the ceiling cannot be what separates them; what differs is whether anything
   came back from inside it. The junk expired at a router and that router said so. The SA_INIT
   produced no such report — CLAUDE.md's gloss on the server row is "dies before hop 3" — which
   means it was discarded inside those same few hops, by a device that sent nothing back.
3. Neither shape could travel past the ceiling, so none of the destinations can be the dropper.
   Google, Cloudflare, Quad9 and GitHub plainly do not run IKE filters, and more to the point never
   saw these packets. Neither did the server under test, nor its provider's edge. (CLAUDE.md
   characterises the margin as ten hops; no per-destination hop count is recorded anywhere in this
   repo, so the argument uses only the ceiling, which is exact. The junk control's time-exceeded is
   itself evidence that the destinations lay beyond it, since a TTL expiry is reported by a router
   that still had the packet to forward and not by the destination — but that is an inference from
   ICMP semantics, not a measured hop count.)
4. Those same first hops forwarded the identical payload when it was addressed to `194.87.49.94`,
   `77.88.8.8` or `213.180.204.242`. So the decision is a function of **payload shape × destination
   address**, not of payload shape alone.

The foreign/domestic labelling is CLAUDE.md's. What was actually observed is a split by destination
*address*: the public-resolver addresses on the dropped side are anycast, and where any of them was
being served from on the day was not measured.

Stated at its real strength: on this one subscriber line, on 2026-09-08, UDP whose payload parses as
an ISAKMP header was discarded within the first three hops when addressed to any of the five foreign
destinations tried, and forwarded when addressed to any of the three domestic ones. Those hops are
inside the subscriber's own ISP. CLAUDE.md names the mechanism a DPI middlebox, which fits the
observation, though no device was identified or inspected. That is one line on one day. It is not a
description of that provider's network, not a claim about its other subscribers, and not a claim
about anybody's policy or intent.

## The three properties, and what each one rules out

**It is stateful, and the first packet of a flow decides.** 200 retransmits on one 5-tuple
produced zero replies, so this is not probabilistic loss. Prime the same 5-tuple with one junk
datagram first, and a byte-identical `IKE_SA_INIT` sails through and `pluto` answers it in full.
The tuple's verdict is set by its first packet and then held. This rules out the entire
"just retry / raise the timeout" class of response, and it explains the empty server log exactly:
a real client's first packet *is* the `IKE_SA_INIT`, so every client poisons its own tuple before
the server is ever allowed to hear it. Zero negotiations in the log is not a server that rejects
clients. It is a server that has never been spoken to, not once.

**It is destination-port-independent.** IKE payloads were dropped on 53, 443, 1701, 12345 and
51820 alike, while same-size junk arrived on every one of them. The classifier reads the payload,
not the port. **Moving IKEv2 to a non-standard port cannot work** — do not spend an afternoon on
it. This was a separate hand-run measurement, and `path` cannot reproduce it: its walk sends to
udp/500, hardcoded in `cmd_path`, so it sweeps TTLs and never ports.

**It applies identically over IPv6.** That rules out NAT, CGNAT and anything else stateful about
address translation on the line. The IPv6 leg has to use `probe`: `path` is IPv4-only, because
its TTL walk reads ICMP off the socket error queue via `IP_RECVERR`.

## How to repeat it

All four modes are read-only. The script changes nothing, starts nothing, and writes nothing
outside `/tmp`; it is safe on a live server.

From the failing client's own network, which needs no server access at all:

```bash
bash scripts/diagnose-ikev2.sh probe <server-ip>
bash scripts/diagnose-ikev2.sh path  <server-ip>
```

`probe` sends, to udp/500 and udp/4500 in turn, one genuine `IKE_SA_INIT` and one junk datagram of
exactly the same size, under different markers. On 4500 it prefixes the four zero bytes of the
non-ESP marker. It waits up to 3s for a reply to the genuine packet (1s for the control, which no
responder answers) and requires that reply to carry the initiator SPI it just sent and to be an
`IKE_SA_INIT` response, so a stray scan datagram landing on the ephemeral port cannot be counted as
the server answering. Reading it:

- a reply (exit 0) — IKE works between *that host* and the server, and exonerates *that path*
  only. Run it from the failing client's own network or it answers a different question;
- no reply (exit 1) — go on to `path`;
- `COULD NOT BE SENT` (exit 2) — the datagram never left this host. Local firewall or routing. It
  says nothing about the path or the server. A target that does not resolve also exits 2, for the
  same reason: it is not a statement about the path either.

`path` is the stronger test and needs no second host. It walks TTL 1 through 20, sending at each
TTL one genuine SA_INIT and one same-size junk datagram, interleaved so both meet identical path
conditions, and reads the resulting ICMP off the socket error queue; it stops early if the
destination itself answers a walk packet. The destination port is **udp/500, hardcoded** — this
command varies the TTL, nothing else. In its output a hop prints its address when it returned
time-exceeded, `-` when nothing came back, and `<ip>!` when it returned destination-unreachable.
That `!` matters: a reject is the filter announcing itself, and must **not** be read as "IKE
travelled this far". After the walk it sends one SA_INIT at a normal TTL, because a reply is the
only positive proof the destination was reached at all. Its verdicts:

- IKE reached the destination and was answered — nothing on this path filters IKE (exit 0);
- IKE was actively rejected at hop *N* — that device refused the packet rather than forwarding it,
  and sits upstream of the destination (exit 1);
- fewer than two hops answered ICMP for the **junk** control — inconclusive. The test is keyed on
  the junk count alone, deliberately: the shape under suspicion cannot calibrate the walk. Many
  networks suppress ICMP entirely and this cannot see through that (exit 2);
- junk reached a later hop than IKE — the device at or just before hop `ike_last + 1` is
  classifying the ISAKMP payload and dropping it, upstream of the destination. **This is the
  result that line produced** (exit 1);
- both shapes travelled equally far and no IKE reply came back — no content-based filtering is
  visible on this path, and the thing to examine is the destination itself (exit 1).

Then the control that makes the finding destination-keyed rather than merely path-keyed: run
`path` a second time against a host you know answers IKE. `194.87.49.94` served as that host
here. If the second target's SA_INIT survives the very hop the first one died at, the filter is
keyed on destination and no change on the server can affect it. The script prints that follow-up
itself after any walk that actually ran, and suppresses it on exit 2 — advising a comparison
after a trace that never happened reads as though one had completed.

On the server, for the other half of the picture:

```bash
sudo bash scripts/diagnose-ikev2.sh listen
sudo bash scripts/diagnose-ikev2.sh local
```

`listen` needs root and `tcpdump`. It prints the local state survey first, then captures for 90s
(`CAPTURE_SECONDS`) with `tcpdump -nni any -A -c 200` over udp/500, udp/4500, udp/1701 and proto
50, keeping the raw capture under `/tmp`. `-A` is load-bearing: without the ASCII payload the
`DIAGIKE`/`DIAGJUNK` markers are invisible and the verdict cannot say which shape arrived, which
is the entire discriminator. `tcpdump` taps before netfilter's INPUT chain, so anything reaching
the NIC shows up even if a firewall would later drop it. Four outcomes:

- `DIAGIKE` seen — IKE reaches the box. Look at the server (the FORWARD rules below) or at the
  client's profile;
- only `DIAGJUNK` seen — hypothesis (C). The ports are open; IKE specifically is not allowed
  through. Nothing on the server can fix it;
- traffic on 500/4500 but neither marker — the probe was not run, or was run against a different
  address. Kept separate from the line below on purpose: "my markers did not arrive" and "nothing
  arrived" are different facts, and only the second is about filtering;
- nothing at all — hypothesis (A) or (B): udp/500 and udp/4500 are dropped outright. Separate the
  two by probing from a second, unrelated network.

`local` is the same state survey with no capture: container state, listeners (bound on a *global*
address, not merely bound), ufw, the INPUT path across the whole ruleset including the `ufw-*`
sub-chains, the FORWARD rules, the relevant sysctls, and strongSwan's own view. Only `listen`
enforces root, but everything from the INPUT check onward reads `iptables`: without root, `local`
prints `cannot read iptables (needs root)` and returns there, so the FORWARD check — the failure
mode described below — is simply not performed. The script's own usage line shows `local` without
`sudo`; run it with.

One standing caveat on `listen`: a probe from some other network exonerates only that other
network. It says nothing whatsoever about the failing client.

## A separate failure mode, which must not be conflated with the above

Even when IKE does reach the server, IKEv2 IPv4 clients can establish an SA and carry no traffic
at all. This is `ikev2ctl.ensure_ipv4_forwarding`, it is a genuine fault *on the server*, and it
has nothing to do with the filter above. Conflating the two wastes days in both directions.

IKEv2 IPv4 clients are assigned from the image's `XAUTH_POOL` — `192.168.43.10-192.168.43.250`
by default, inside `XAUTH_NET` — and **not** from `L2TP_NET`, `192.168.42.0/24`. Unlike L2TP they
have no ppp interface, so there is no per-client interface for a rule to match on. Without a
`net0`↔`net0` accept pair the packets are not forwarded, and nothing is logged. The SA is up, the client shows connected, and nothing moves.

`hwdsl2`'s `run.sh` does install that pair, so a healthy box already has it — but its idempotence
guard tests a rule in the **nat** table while the accepts it protects live in **filter**. Anything
that clears filter alone loses them with nothing to put them back, and the loss is invisible until
somebody notices IKEv2 carries no traffic. Re-ensuring them costs two `iptables -C` calls. That is
why `vpnctl` needs root, and why `vpn-stack.service` (oneshot, `After=docker.service`) re-applies
them at boot: raw `iptables -I` inserts have no persistence of their own.

The instructive part is how this went unnoticed. The subnet was hardcoded as `192.168.42.0/24`
until 2026-09-08 — the L2TP pool. Every rule installed therefore protected addresses no IKEv2
client is ever given, and **both** health checks, `scripts/smoke.sh` and `diagnose-ikev2.sh`,
asserted that same wrong subnet. They reported green inside exactly the failure they exist to
catch. A check that restates the code's assumption has stopped being a check — the same error, in
a different costume, as the junk datagram above.

All three call sites now ask the container which pool it hands out, in this precedence:

1. `conn ikev2-cp`'s own `rightaddresspool`, read from `/etc/ipsec.d/ikev2.conf`;
2. `VPN_XAUTH_NET` from the container's environment;
3. the image default, `192.168.43.0/24`.

The order is the whole fix and it does not commute. `ikev2.sh` builds the pool from `XAUTH_POOL`,
while `run.sh` uses `XAUTH_NET` for the firewall rules *it* writes, so the two can be set apart.
`rightaddresspool` is literally the range `pluto` assigns — observed truth. `XAUTH_NET` is a
statement of intent by a different script. Preferring the net would reproduce this very bug for
anyone who set only one of the two. (The pool branch assumes a /24, which is what every stock
deployment uses.) Same principle as IKEv2 certificates elsewhere in this repo: reconcile from
observed truth, not from a remembered constant.

Two details follow from the same "a broken check is worse than no check" reasoning. Every answer
carries its provenance — `conn ikev2-cp rightaddresspool`, `VPN_XAUTH_NET`, or a third label that
names the image default and says the container never answered (`image default -- container config
unreadable` in the Python, `image default, container unreadable` in the two shell copies) — so a
fallback cannot be mistaken for a real answer. And both shell copies validate the address before
handing it to `iptables`, because an unparseable value makes `iptables -C` fail in a way
indistinguishable from "the rule is missing", which would report a healthy box as broken.

## Limits

**One vantage point.** One subscriber line, one provider, one day. Eight destinations: the server
under test plus seven third-party addresses — five foreign in total, three domestic. Everything
above describes what that line did. It does not establish how much of that provider's network
behaves this way, and the word "policy" appears nowhere on purpose.

**Not tested: connecting from a different ISP.** It is expected to work outright, and it was never
tried, because there was no third vantage point. That is the largest gap in this report, and
nothing here should be read as though it had been closed.

**Not reproduced by the tooling:** the destination sweep in the table above, the port sweep (53,
443, 1701, 12345, 51820), and the priming result. All three were hand-run. `path <ip>` reproduces
the localisation for one destination on udp/500; running it a second time against a host known to
answer IKE reproduces the destination keying. Nothing in the repo replays the port sweep — the port
is hardcoded — and nothing replays the priming.

**A reading imposed on the record:** the table's cells are fractions over 3 and what that
denominator counted is not written down. "Three attempts, success = an ICMP error from inside the
ceiling" is how this document reads them. The reading bears on how strong each cell is, not on
which way it points.

**Not used, because it is not recorded:** the distance from the TTL ceiling to the destinations.
The ceiling, 3, is exact. "Ten hops short" is CLAUDE.md's characterisation, and no per-destination
hop count exists anywhere in this repo, so the argument above is made from the ceiling alone.

What would falsify the conclusion:

- a genuine `IKE_SA_INIT` from that same line, on a fresh 5-tuple, answered by the server under
  test. That alone retires the whole finding;
- `path` toward the server showing IKE and junk travelling equally far with no reply at the end.
  The script reports that case separately, and it points back at the destination;
- the same IKE-versus-junk divergence appearing toward `194.87.49.94` or the Yandex addresses.
  That breaks the destination keying, and with it the inference that the decision is made on the
  client side;
- the divergence hop resolving to an address outside the subscriber's ISP. The localisation
  survives — something upstream of the destination is still classifying payloads — but the
  attribution does not;
- IKEv2 failing this same way from an unrelated ISP to the same server. That moves the suspect
  back toward the server's own prefix, and it is the one check nobody has run.

One further data point about the filter's scope, not a recommendation: the other two transports
this stack serves, VLESS-REALITY on `10443/tcp` and Hysteria2 on `20443/udp`, were unaffected on
this same line.
