import subprocess

from vpnctl.paths import ROOT


def check_config() -> tuple[bool, str]:
    result = subprocess.run(
        [
            "docker", "compose", "run", "--rm", "--no-deps",
            "sing-box", "check",
            "-C", "/etc/sing-box/common",
            "-C", "/etc/sing-box/vless-reality",
            "-C", "/etc/sing-box/hysteria2",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


def apply() -> tuple[bool, str]:
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "--no-deps", "sing-box"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output
