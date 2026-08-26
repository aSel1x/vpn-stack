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
    return _docker_exec("ikev2.sh", "--removeclient", name)


def list_clients() -> tuple[bool, str]:
    return _docker_exec("ikev2.sh", "--listclients")


def export_client(name: str) -> tuple[bool, str, str | None]:
    """Export an IKEv2 client's .p12 bundle to exports/.

    Returns (ok, message, path_or_none). The exact filename ikev2.sh writes
    inside the container hasn't been confirmed against a live instance yet --
    this tries the conventional `<name>.p12` and surfaces the raw --listclients
    output on failure so the real name can be spotted and this fixed.
    """
    ok, output = _docker_exec("ikev2.sh", "--exportclient", name)
    if not ok:
        return False, output, None

    EXPORTS_DIR.mkdir(exist_ok=True)
    dest = EXPORTS_DIR / f"{name}-ikev2.p12"
    cp = subprocess.run(
        ["docker", "cp", f"{IKEV2_CONTAINER_NAME}:/etc/ipsec.d/{name}.p12", str(dest)],
        capture_output=True,
        text=True,
    )
    if cp.returncode != 0:
        _, listing = list_clients()
        return (
            False,
            f"--exportclient succeeded but couldn't docker cp the .p12 out "
            f"(tried /etc/ipsec.d/{name}.p12): {cp.stderr.strip()}\n"
            f"--listclients output for reference:\n{listing}",
            None,
        )
    return True, f"Exported to {dest}", str(dest)
