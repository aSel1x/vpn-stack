"""The keyring: one file per secret under STATE_DIR/secrets, 0600.

Secrets stop living inside the config files they end up in. That inversion is
what lets `render` be a pure function of (secrets, users) -- and what lets the
structural half of the config (ports, SNI, masquerade domain) move back into
git, closing the trade-off CLAUDE.md documents.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from vpnctl.paths import SECRETS_DIR


class MissingSecret(KeyError):
    pass


@dataclass(frozen=True)
class Secrets:
    """An immutable snapshot of the keyring. Pure input to render()/share()."""

    values: dict[str, bytes]

    def raw(self, name: str) -> bytes:
        try:
            return self.values[name]
        except KeyError:
            raise MissingSecret(
                f"secret {name!r} is missing from the keyring "
                f"(expected {SECRETS_DIR / name}). Run `vpnctl bootstrap`."
            ) from None

    def text(self, name: str) -> str:
        return self.raw(name).decode().strip()

    def has(self, name: str) -> bool:
        return name in self.values


def load(directory: Path | None = None) -> Secrets:
    base = directory or SECRETS_DIR
    values: dict[str, bytes] = {}
    if base.is_dir():
        for path in sorted(base.rglob("*")):
            # Skip our own half-written temporaries and anything empty: a
            # zero-length file is not a secret, and counting it as one makes
            # `bootstrap` refuse to replace it.
            if path.is_file() and path.stat().st_size > 0 and path.suffix != ".tmp":
                values[str(path.relative_to(base))] = path.read_bytes()
    return Secrets(values=values)


def write(name: str, content: bytes, directory: Path | None = None) -> Path:
    """Create at 0600 and replace atomically.

    write_bytes() truncates first and chmods after, so an interrupted bootstrap
    could leave a zero-length file that load()/has() count as present -- and
    `bootstrap` would then skip regenerating it, leaving a server with an empty
    REALITY key that only fails at render time.
    """
    base = directory or SECRETS_DIR
    path = base / name
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return path
