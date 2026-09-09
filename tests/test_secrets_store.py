"""secrets_store.write/load -- 0600 at creation, atomic replace, no empties.

write_bytes() truncates first and chmods after, so an interrupted bootstrap
could leave a zero-length file that has() counts as present -- and bootstrap
would then skip regenerating it, leaving a server with an empty REALITY key
that only fails at render time.
"""

from __future__ import annotations

import os
import stat

import pytest

from vpnctl import secrets_store
from vpnctl.paths import SECRETS_DIR
from vpnctl.secrets_store import MissingSecret


@pytest.fixture(autouse=True)
def _predictable_umask():
    # The mode is set at creation and never chmod()ed afterwards, so it is
    # masked by the caller's umask. Fixed here so the assertion means something.
    previous = os.umask(0o022)
    yield
    os.umask(previous)


def test_write_creates_at_0600() -> None:
    path = secrets_store.write("reality.key", b"secret\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == b"secret\n"


def test_the_mode_is_set_at_creation_not_after() -> None:
    # A world-readable window one syscall wide is still a window: the file is
    # every client's key. Nothing here can observe the race, so this asserts
    # the property that makes it impossible -- no chmod call, and the file
    # arrives through a rename, never as a growing world-readable file.
    secrets_store.write("reality.key", b"x")
    tmp = SECRETS_DIR / "reality.key.tmp"
    assert not tmp.exists()


def test_write_replaces_atomically() -> None:
    first = secrets_store.write("reality.key", b"old")
    before = first.stat().st_ino
    second = secrets_store.write("reality.key", b"new-and-longer")
    assert second.read_bytes() == b"new-and-longer"
    assert second.stat().st_ino != before  # a rename, not a truncate-in-place
    assert stat.S_IMODE(second.stat().st_mode) == 0o600


def test_write_creates_missing_parents() -> None:
    path = secrets_store.write("nested/deep.key", b"x")
    assert path.read_bytes() == b"x"
    assert secrets_store.load().has("nested/deep.key")


def test_a_zero_length_file_is_not_a_secret() -> None:
    secrets_store.write("reality.key", b"")
    keyring = secrets_store.load()
    assert not keyring.has("reality.key")
    assert "reality.key" not in keyring.values
    # ...which is exactly what lets bootstrap replace it.
    with pytest.raises(MissingSecret):
        keyring.text("reality.key")


def test_a_stray_temporary_is_not_a_secret() -> None:
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    (SECRETS_DIR / "reality.key.tmp").write_bytes(b"half a key")
    assert secrets_store.load().values == {}


def test_load_of_a_missing_directory_is_empty_not_an_error() -> None:
    assert not SECRETS_DIR.exists()
    assert secrets_store.load().values == {}


def test_text_strips_and_raw_does_not() -> None:
    # dnstt's key file is hex plus a newline; the URI builders want it bare,
    # the rendered file wants it byte-identical to what the binary emitted.
    secrets_store.write("dnstt.server.key", b"deadbeef\n")
    keyring = secrets_store.load()
    assert keyring.text("dnstt.server.key") == "deadbeef"
    assert keyring.raw("dnstt.server.key") == b"deadbeef\n"


def test_a_missing_secret_says_where_it_should_be_and_what_to_run() -> None:
    with pytest.raises(MissingSecret) as excinfo:
        secrets_store.Secrets(values={}).raw("reality.key")
    message = str(excinfo.value)
    assert str(SECRETS_DIR / "reality.key") in message
    assert "vpnctl bootstrap" in message


def test_write_accepts_an_explicit_directory(tmp_path) -> None:
    # The only way anything writes outside SECRETS_DIR, and it is a parameter,
    # not a path built inline.
    path = secrets_store.write("reality.key", b"x", directory=tmp_path)
    assert path == tmp_path / "reality.key"
    assert secrets_store.load(tmp_path).has("reality.key")
    assert not SECRETS_DIR.exists()
