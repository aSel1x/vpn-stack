import os
import subprocess

from vpnctl.paths import IKEV2_CONTAINER_NAME, ROOT, STATE_DIR


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


def apply_env() -> tuple[bool, str]:
    """Recreate the ikev2 container so it picks up new .env values.

    The hwdsl2 image only reads VPN_ADDL_USERS/VPN_ADDL_PASSWORDS at startup,
    so unlike sing-box this briefly drops *every* active session this container
    serves -- L2TP, Cisco IPsec and IKEv2 alike, not just the user being added
    or removed. IKEv2 *certificates* survive (they live in the ikev2-vpn-data
    volume, not in the container); live IKEv2 *tunnels* do not.

    A failure to (re)install the FORWARD rules fails this call rather than
    being appended to a string the caller discards on success: without those
    rules IKEv2 IPv4 clients still connect but carry no traffic, which is
    silent and expensive to diagnose.
    """
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "--no-deps", "ikev2"],
        cwd=ROOT,
        env={**os.environ, "VPN_STATE": str(STATE_DIR)},
        capture_output=True,
        text=True,
        timeout=300,
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        return False, output

    fw_ok, fw_output = ensure_ipv4_forwarding()
    if not fw_ok:
        return False, (
            f"{output}\nthe ikev2 container restarted, but the IKEv2 IPv4 FORWARD "
            f"rules could NOT be applied: {fw_output}\nIKEv2 clients will connect "
            "and carry no traffic until this is fixed (needs root)."
        )
    return True, output


# hwdsl2/ipsec-vpn-server's default IPv4 pool shared by both L2TP and IKEv2
# clients (not overridden by anything in ikev2/.env for this deployment --
# confirmed against the live nftables ruleset).
_IKEV2_IPV4_NET = "192.168.42.0/24"


def _default_iface() -> str | None:
    result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    parts = result.stdout.split()
    return parts[parts.index("dev") + 1] if "dev" in parts else None


def ensure_ipv4_forwarding() -> tuple[bool, str]:
    """Insert the FORWARD-chain accepts run.sh never adds for its own L2TP_NET pool.

    Confirmed against a live instance's nftables ruleset: run.sh installs
    net0<->net0 FORWARD accepts for XAUTH_NET (Cisco IPsec, 192.168.43.0/24)
    and for its IPv6 pool, plus ppp+<->net0 accepts for L2TP-over-ppp -- but
    never a net0<->net0 pair for L2TP_NET (192.168.42.0/24) itself. IKEv2
    IPv4 clients share that pool but, unlike L2TP, have no ppp interface --
    their decrypted traffic reappears directly on the physical interface via
    XFRM -- so without this rule their IKE/IPsec SA establishes fine but no
    traffic can ever forward: FORWARD's default DROP policy swallows it
    silently, with nothing logged. Idempotent (checks before inserting);
    safe to call anytime, including after every ikev2 container restart.
    """
    iface = _default_iface()
    if not iface:
        return False, "could not determine default network interface"

    rules = [
        ["-i", iface, "-d", _IKEV2_IPV4_NET, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ["-s", _IKEV2_IPV4_NET, "-o", iface, "-j", "ACCEPT"],
    ]
    for rule in rules:
        check = subprocess.run(["iptables", "-C", "FORWARD", *rule], capture_output=True, text=True)
        if check.returncode == 0:
            continue
        add = subprocess.run(["iptables", "-I", "FORWARD", "1", *rule], capture_output=True, text=True)
        if add.returncode != 0:
            return False, (add.stdout + add.stderr).strip()
    return True, f"IKEv2 IPv4 FORWARD rules ensured on {iface} for {_IKEV2_IPV4_NET}"


def add_client(name: str) -> tuple[bool, str]:
    return _docker_exec("ikev2.sh", "--addclient", name)


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
            ["docker", "exec", IKEV2_CONTAINER_NAME,
             "cat", f"/etc/ipsec.d/{name}{suffix}"],
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0 or not result.stdout:
            problems.append(f"  FAILED {name}{suffix} ({label}): {result.stderr.decode().strip()}")
            continue
        bundles[f"{name}{dest_suffix}"] = result.stdout

    # Read, then remove. Regenerating them is one --exportclient away; leaving
    # them is a credential sitting on disk for as long as the volume lives.
    _docker_exec(
        "sh", "-c",
        "rm -f " + " ".join(f"/etc/ipsec.d/{name}{sfx}" for sfx, _, _ in _CLIENT_FILES),
    )

    if not bundles:
        _, listing = list_clients()
        return False, (
            "None of the client files could be read:\n" + "\n".join(problems)
            + f"\n--listclients output for reference:\n{listing}"
        ), {}

    lines = [f"  {fn}  ({len(b)} bytes)" for fn, b in bundles.items()]
    if problems:
        lines += problems
    return True, "Exported:\n" + "\n".join(lines), bundles
