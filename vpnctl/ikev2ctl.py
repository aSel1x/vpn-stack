import subprocess

from vpnctl.paths import EXPORTS_DIR, IKEV2_CONTAINER_NAME, ROOT


def _docker_exec(*args: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["docker", "exec", IKEV2_CONTAINER_NAME, *args],
        capture_output=True,
        text=True,
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
    so unlike sing-box this briefly drops every active L2TP/Cisco IPsec
    session, not just the one being added/removed -- IKEv2 clients (managed
    separately via ikev2.sh) are unaffected.
    """
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "--no-deps", "ikev2"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (result.stdout + result.stderr).strip()
    ok = result.returncode == 0
    if ok:
        fw_ok, fw_output = ensure_ipv4_forwarding()
        if not fw_ok:
            output += f"\nwarning: could not ensure IKEv2 IPv4 forwarding rules: {fw_output}"
    return ok, output


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


def export_client(name: str) -> tuple[bool, str, list[str]]:
    """Export an IKEv2 client's credential bundles to exports/.

    Returns (ok, message, exported_paths).
    """
    ok, output = _docker_exec("ikev2.sh", "--exportclient", name)
    if not ok:
        return False, output, []

    EXPORTS_DIR.mkdir(exist_ok=True)
    exported = []
    lines = []
    for src_suffix, dest_suffix, label in _CLIENT_FILES:
        dest = EXPORTS_DIR / f"{name}{dest_suffix}"
        cp = subprocess.run(
            ["docker", "cp", f"{IKEV2_CONTAINER_NAME}:/etc/ipsec.d/{name}{src_suffix}", str(dest)],
            capture_output=True,
            text=True,
        )
        if cp.returncode != 0:
            lines.append(f"  FAILED {name}{src_suffix} ({label}): {cp.stderr.strip()}")
            continue
        exported.append(str(dest))
        lines.append(f"  {dest}  ({label})")

    if not exported:
        _, listing = list_clients()
        return (
            False,
            "None of the client files could be copied out:\n" + "\n".join(lines)
            + f"\n--listclients output for reference:\n{listing}",
            [],
        )
    return True, "Exported:\n" + "\n".join(lines), exported
