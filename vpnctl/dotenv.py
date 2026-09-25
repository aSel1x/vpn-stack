"""Read /etc/vpn-stack/.env the way `docker compose` reads it.

That agreement is the whole point of this module. The same file is read twice by
two different programs -- compose interpolates `${VPN_DNSTT_ZONE}` into the dnstt
command line, vpnctl reads it here to build share links and to decide whether
`protocol on dnstt` may proceed -- and any disagreement between the two readers
is silent by construction: the container serves one zone, the QR card in
somebody's hand names another, and both halves look right on their own.
"""

from pathlib import Path


def read(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        # `export K=V` is what an operator who has edited a shell profile writes,
        # and compose accepts it; treating `export VPN_DNSTT_ZONE` as the key
        # meant the value was simply never found and dnstt looked unconfigured.
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[len("export") :].lstrip()
        key, _, value = line.partition("=")
        values[key.strip()] = _unquote(value.strip())
    return values


def _unquote(value: str) -> str:
    """Strip one matching pair of wrapping quotes, as compose does.

    `VPN_DNSTT_ZONE="tun.example.com"` is a perfectly ordinary thing to write and
    compose hands the container `tun.example.com`; keeping the quotes here gave
    every share link the literal `"tun.example.com"` instead -- a zone no
    resolver will ever answer for, from a file the operator had filled in
    correctly. The same trap sits under VPN_SERVER_HOST, where the damage is a
    client config pointing at a quoted host.

    Only a *matching* pair that wraps the whole value goes: a lone quote is data
    (compose leaves it alone too), and stripping it would invent a value nobody
    wrote. A trailing comment is deliberately NOT stripped, because compose does
    not strip one either -- `scripts/provision-host.sh` says so where it writes
    the commented `#VPN_DNSTT_ZONE=` hint, and that comment is only true while
    this reader stays literal.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value
