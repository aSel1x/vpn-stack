import ipaddress
import subprocess

from vpnctl.paths import IKEV2_CONTAINER_NAME


def _docker_exec(*args: str) -> tuple[bool, str]:
    # ikev2.sh prompts on some paths; every caller passes -y, but a timeout
    # means a missed one blocks `vpn user add` forever instead of failing.
    result = subprocess.run(
        ["docker", "exec", IKEV2_CONTAINER_NAME, *args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


def is_running() -> bool:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", IKEV2_CONTAINER_NAME],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


# The pool IKEv2 clients are actually assigned addresses from.
#
# This said 192.168.42.0/24 until 2026-09-08, and that was the wrong subnet.
# hwdsl2's run.sh defines two: L2TP_NET (192.168.42.0/24) and XAUTH_NET
# (192.168.43.0/24). ikev2.sh builds `conn ikev2-cp` with `rightaddresspool`
# pointing at the *XAUTH* pool, so an IKEv2 client is handed a .43 address and
# never a .42 one -- confirmed on the live box:
#   rightaddresspool=192.168.43.10-192.168.43.250,fddd:500:500:500::1000-...
# Every rule this function installed therefore protected a subnet no client is
# ever given, and both health checks (scripts/smoke.sh, scripts/diagnose-ikev2.sh)
# asserted that same wrong subnet -- reporting green in precisely the failure
# they exist to catch. The rules that do carry IKEv2 traffic today come from
# the image's own run.sh, which this repo neither owns nor verifies.
#
# The pool is overridable (VPN_XAUTH_POOL, with VPN_XAUTH_NET moving the rules
# run.sh writes), so the value is read from the running container and this is
# only the fallback for when it cannot be. Same principle as IKEv2
# certificates: reconcile from observed truth, not from a remembered intent.
_IKEV2_IPV4_NET_DEFAULT = "192.168.43.0/24"


def _covering_net(entry: str) -> str | None:
    """The smallest network holding one `first-last` pool entry, or None.

    Derived from BOTH ends rather than assuming a /24 on the first. A pool of
    192.168.43.10-192.168.44.250 is a straddling range, and calling it
    192.168.43.0/24 leaves half of it outside every rule and outside both
    health checks -- green, while the clients holding those addresses forward
    nothing. The covering network can be wider than the pool
    (summarize_address_range splits a straddling range into several networks;
    what one rule can name is the supernet holding all of them), and wider is
    the safe direction: these accepts gate forwarding for addresses this server
    hands out, and an address inside the covering network but outside the pool
    is one pluto never assigns to anybody.

    IPv6 entries return None -- see ensure_ipv4_forwarding on why that half of a
    dual-stack pool is out of scope rather than silently handed to iptables.
    """
    bounds = [b.strip() for b in entry.strip().split("-") if b.strip()]
    if not bounds:
        return None
    try:
        if len(bounds) == 1 and "/" in bounds[0]:
            # rightaddresspool takes a CIDR as happily as a range.
            block = ipaddress.ip_network(bounds[0], strict=False)
            first, last = block.network_address, block.broadcast_address
        else:
            first = ipaddress.ip_address(bounds[0])
            last = ipaddress.ip_address(bounds[-1])
    except ValueError:
        return None
    if first.version != 4 or last.version != 4 or last < first:
        return None
    covering = next(ipaddress.summarize_address_range(first, last))
    while covering.broadcast_address < last:
        covering = covering.supernet()
    return str(covering)


def pool_network(conf: str | None, xauth_net: str | None) -> tuple[str, str]:
    """(network, how we know it) from what the container was able to tell us.

    Pure, and deliberately separate from the two `docker exec`s that fetch its
    arguments: what it returns goes straight to `iptables`, and the last time it
    was wrong -- a plausible constant, 192.168.42.0/24 -- every rule vpnctl
    installed protected addresses no IKEv2 client is ever given, while both
    health checks asserted that same constant and reported green. A parse with
    no test is how that survives a year; this one is exercised against real
    ikev2.conf text with no container anywhere.

    `conn ikev2-cp`'s own rightaddresspool is authoritative because it is
    literally the range pluto hands out. VPN_XAUTH_NET is only a fallback:
    run.sh uses it for its *firewall* rules while ikev2.sh builds the pool from
    VPN_XAUTH_POOL, so the two can be set apart, and preferring the net would
    reproduce exactly the bug above for anyone who set only one of them. It is
    validated before use, because an unparseable address makes `iptables -C`
    fail in a way indistinguishable from "the rule is missing" -- reporting a
    healthy box as broken.

    Either source failing falls through to the image default, and the provenance
    then says which one failed: a default that reads like an answer is the shape
    of the original mistake, so the caller has to be able to see that nothing
    ever answered.
    """
    why = "container config unreadable"
    if conf:
        pool = next(
            (
                line.strip().split("=", 1)[1]
                for line in conf.splitlines()
                if line.strip().startswith("rightaddresspool=")
            ),
            None,
        )
        # The first match, which is what scripts/smoke.sh and
        # scripts/diagnose-ikev2.sh also take: ikev2.sh writes exactly one
        # rightaddresspool, in `conn ikev2-cp`.
        if pool is None:
            why = "ikev2.conf names no rightaddresspool"
        else:
            for entry in pool.split(","):
                net = _covering_net(entry)
                if net:
                    return net, "conn ikev2-cp rightaddresspool"
            why = "conn ikev2-cp offers no IPv4 pool"

    if xauth_net:
        try:
            block = ipaddress.ip_network(xauth_net.strip(), strict=False)
        except ValueError:
            why = f"VPN_XAUTH_NET={xauth_net.strip()!r} does not parse as a network"
        else:
            if block.version == 4:
                return str(block), "VPN_XAUTH_NET"
            why = f"VPN_XAUTH_NET={xauth_net.strip()!r} is not IPv4"

    return _IKEV2_IPV4_NET_DEFAULT, f"image default -- {why}"


def _ikev2_ipv4_net() -> tuple[str, str]:
    """Ask the container the two questions pool_network decides between."""
    ok, conf = _docker_exec("cat", "/etc/ipsec.d/ikev2.conf")
    got_conf = conf if ok else None
    ok, value = _docker_exec("printenv", "VPN_XAUTH_NET")
    return pool_network(got_conf, value if ok else None)


def _default_iface() -> str | None:
    result = subprocess.run(
        ["ip", "route", "show", "default"], capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    parts = result.stdout.split()
    return parts[parts.index("dev") + 1] if "dev" in parts else None


def _forward_rules(iface: str, net: str) -> list[list[str]]:
    """The accept pair, written once so ensure and remove cannot disagree.

    Both directions, because one accept without the other still means no
    traffic -- and checking only the outbound one is how a missing pair hid
    before.
    """
    return [
        [
            "-i",
            iface,
            "-d",
            net,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        ["-s", net, "-o", iface, "-j", "ACCEPT"],
    ]


def ensure_ipv4_forwarding() -> tuple[bool, str]:
    """Guarantee the net0<->net0 FORWARD accepts IKEv2 IPv4 clients depend on.

    IKEv2 IPv4 clients draw from XAUTH_NET and, unlike L2TP, have no ppp
    interface -- their decrypted traffic reappears directly on the physical
    interface via XFRM. Without a net0<->net0 accept pair their IKE/IPsec SA
    establishes fine but no traffic can ever forward: FORWARD's default DROP
    policy swallows it silently, with nothing logged.

    run.sh does install that pair, so on a healthy box these are already
    present -- but its idempotence guard tests a rule in the *nat* table while
    the accepts it protects live in *filter*. Anything that clears filter alone
    loses them with nothing to put them back, and the loss is invisible until
    someone notices IKEv2 carries no traffic. Re-ensuring them here costs two
    iptables -C calls and closes that hole.

    IKEv2 over IPv6 is deliberately out of scope: the pool's IPv6 half
    (fddd:500:500:500::1000-... on a stock image) gets no ip6tables pair here,
    so an IPv6 IKEv2 client depends entirely on the image's own rules. Scoping
    it out is stated rather than implied because the alternative -- a parse that
    quietly drops the half it cannot handle -- is the shape of the bug this
    whole area already had once.

    Idempotent (checks before inserting); safe to call anytime, including after
    every ikev2 container restart.
    """
    iface = _default_iface()
    if not iface:
        return False, "could not determine default network interface"

    net, provenance = _ikev2_ipv4_net()
    for rule in _forward_rules(iface, net):
        check = subprocess.run(
            ["iptables", "-C", "FORWARD", *rule], capture_output=True, text=True
        )
        if check.returncode == 0:
            continue
        add = subprocess.run(
            ["iptables", "-I", "FORWARD", "1", *rule], capture_output=True, text=True
        )
        if add.returncode != 0:
            return False, (add.stdout + add.stderr).strip()
    return True, f"IKEv2 IPv4 FORWARD rules ensured on {iface} for {net} ({provenance})"


def remove_ipv4_forwarding() -> tuple[bool, str]:
    """Take that pair back out, for a server that no longer serves IKEv2.

    Nothing used to remove them, so `protocol off ikev2` left two raw inserts in
    FORWARD with no owner, no persistence and no protocol behind them -- and the
    next person to read the chain had no way to tell them from a rule somebody
    meant. An ensure with no mirror is a rule that accumulates.

    Deleted while `-C` still matches, up to a bound, because the image's own
    run.sh installs the identical pair and identical rules are indistinguishable
    to iptables: there is no owner to compare against. Removing the image's copy
    too is acceptable exactly here -- the container it belongs to is going away,
    and it reinstalls its own pair the next time it starts.

    The pool can only be asked of a *running* container, so by the time this
    runs the answer is usually the image default. A server with a custom
    VPN_XAUTH_POOL therefore keeps its rules, and `-C` says so by not matching:
    the provenance in the message is what distinguishes "nothing to remove"
    from "nothing was answering".
    """
    iface = _default_iface()
    if not iface:
        return False, "could not determine default network interface"

    net, provenance = _ikev2_ipv4_net()
    removed = 0
    for rule in _forward_rules(iface, net):
        # A bound rather than `while True`: an iptables that goes on reporting a
        # match it will not delete would otherwise spin for ever inside `apply`.
        for _ in range(8):
            check = subprocess.run(
                ["iptables", "-C", "FORWARD", *rule], capture_output=True, text=True
            )
            if check.returncode != 0:
                break
            delete = subprocess.run(
                ["iptables", "-D", "FORWARD", *rule], capture_output=True, text=True
            )
            if delete.returncode != 0:
                return False, (delete.stdout + delete.stderr).strip()
            removed += 1
    if not removed:
        return True, (f"no IKEv2 IPv4 FORWARD rules to remove for {net} ({provenance})")
    return True, (
        f"removed {removed} IKEv2 IPv4 FORWARD rule(s) on {iface} for {net} "
        f"({provenance})"
    )


def add_client(name: str) -> tuple[bool, str]:
    return _docker_exec("ikev2.sh", "--addclient", name)


def delete_client(name: str) -> tuple[bool, str]:
    """Free a reserved client name, without pretending to revoke anything.

    `--deleteclient` on its own does NOT stop that certificate being accepted --
    the image's own warning says so -- so this is never the way to withdraw
    access; remove_client is. What it does is release the name from the IPsec
    database, which is the only thing standing between a revoked client and a
    fresh certificate under the same name: `--addclient` for a name that is
    merely revoked fails with "already exists", confirmed live.

    `-y` or it blocks on an interactive confirmation prompt.
    """
    return _docker_exec("ikev2.sh", "--deleteclient", name, "-y")


def remove_client(name: str) -> tuple[bool, str]:
    """Revoke, then delete, an IKEv2 client's certificate.

    ikev2.sh has no `--removeclient` -- confirmed against a live instance.
    There's `--deleteclient` and `--revokeclient`; deleteclient's own
    warning says deleting *does not* stop that certificate from still
    being accepted, so revoke is the step that actually blocks access.

    But revoke alone isn't enough either: a revoked name stays reserved
    in the IPsec database, so a later `--addclient` for the same name
    (e.g. re-adding a previously removed user) fails with "already
    exists" -- confirmed live. Deleting *after* revoking is safe (the
    cert is already invalid by then) and frees the name for reuse.
    Both need `-y` or they block on an interactive confirmation prompt.
    """
    ok, output = _docker_exec("ikev2.sh", "--revokeclient", name, "-y")
    if not ok:
        return False, output
    return _docker_exec("ikev2.sh", "--deleteclient", name, "-y")


def list_clients() -> tuple[bool, str]:
    return _docker_exec("ikev2.sh", "--listclients")


def parse_clients(listing: str) -> tuple[set[str], set[str]]:
    """(valid, revoked) from `ikev2.sh --listclients`. Pure.

    Two sets and not one, because a revoked certificate is not a certificate:
    everything upstream treated a single `present` set as "has a working
    profile", so a user who was revoked and is wanted again was never re-issued
    and was then recorded ikev2_provisioned=True -- a profile that cannot
    connect, written down as provisioned. The two states also need different
    repairs (delete then add for a revoked name; nothing but add for an absent
    one), which is exactly the distinction a single set cannot carry.

    The format belongs to an image this repo does not own and hard-codes the CLI
    contract of, which is why it is parsed in one tested place instead of inline:
    a header row whose first field is `Client`, then one row per client with the
    status in the second field. A row in neither status is ignored rather than
    guessed at -- an unknown status must not become a working certificate this
    code believes in.
    """
    valid: set[str] = set()
    revoked: set[str] = set()
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] == "Client":
            continue
        if parts[1] == "valid":
            valid.add(parts[0])
        elif parts[1] == "revoked":
            revoked.add(parts[0])
    return valid, revoked


# (container filename suffix, exports/ filename suffix, human label).
# Confirmed against a live instance: ikev2.sh --exportclient writes all
# three for every client -- .p12 is Windows/Linux only, *not* iOS. iOS
# and macOS need the .mobileconfig (a complete ready-to-import VPN
# profile, not just a bare certificate).
_CLIENT_FILES = [
    (".p12", "-ikev2.p12", "Windows/Linux"),
    (".sswan", "-ikev2.sswan", "Android, strongSwan app"),
    (".mobileconfig", "-ikev2.mobileconfig", "iOS/macOS"),
]


def bundle_label(filename: str) -> str:
    """Which platform a bundle is for, from its name.

    The share page labelled all three "client profile", which is exactly the
    question the recipient is trying to answer when they look at it.
    """
    for _, dest_suffix, label in _CLIENT_FILES:
        if filename.endswith(dest_suffix):
            return label
    return "client profile"


def export_client(name: str) -> tuple[bool, str, dict[str, bytes]]:
    """Produce an IKEv2 client's bundles as bytes.

    Deliberately returns contents rather than writing them: client bundles are
    live credentials, and the old behaviour left a growing directory of them on
    the server forever. The caller streams them to whoever asked.

    ikev2.sh writes them into /etc/ipsec.d, which is the persistent volume --
    so they survive restarts, and they ride along in every backup. They are
    deleted here once read. Verified: the .p12 has an EMPTY password, so each
    leftover file is an unprotected private key granting VPN access.

    Returns (ok, message, {filename: contents}).
    """
    ok, output = _docker_exec("ikev2.sh", "--exportclient", name)
    if not ok:
        return False, output, {}

    bundles: dict[str, bytes] = {}
    problems: list[str] = []
    for suffix, dest_suffix, label in _CLIENT_FILES:
        result = subprocess.run(
            [
                "docker",
                "exec",
                IKEV2_CONTAINER_NAME,
                "cat",
                f"/etc/ipsec.d/{name}{suffix}",
            ],
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0 or not result.stdout:
            problems.append(
                f"  FAILED {name}{suffix} ({label}): {result.stderr.decode().strip()}"
            )
            continue
        bundles[f"{name}{dest_suffix}"] = result.stdout

    # Read, then remove. Regenerating them is one --exportclient away; leaving
    # them is a credential sitting on disk for as long as the volume lives.
    _docker_exec(
        "sh",
        "-c",
        "rm -f " + " ".join(f"/etc/ipsec.d/{name}{sfx}" for sfx, _, _ in _CLIENT_FILES),
    )

    if not bundles:
        _, listing = list_clients()
        return (
            False,
            (
                "None of the client files could be read:\n"
                + "\n".join(problems)
                + f"\n--listclients output for reference:\n{listing}"
            ),
            {},
        )

    lines = [f"  {fn}  ({len(b)} bytes)" for fn, b in bundles.items()]
    if problems:
        lines += problems
    return True, "Exported:\n" + "\n".join(lines), bundles
