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
    return result.returncode == 0, output


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
