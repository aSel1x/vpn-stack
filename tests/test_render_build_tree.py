"""render -- what `apply` decides, and what it does to the disk.

build_tree is the pure half: everything that reaches the disk in a real apply is
decided there, so this is the cheapest place to catch a protocol that overwrites
a sibling's file, a port collision, or a secret nobody generated.

The rest of the file covers write_candidate, promote and prune, which are the
three functions that can destroy the live tree -- two running containers are
bind-mounted inside it, and deleting it out from under them fails silently until
their next restart.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vpnctl import protocols, render, secrets_store
from vpnctl.paths import RENDERED_LINK, SING_BOX_COMMON
from vpnctl.protocols import Kind, Port, Protocol, RenderError
from vpnctl.secrets_store import MissingSecret

ALL = protocols.ordered()

# What a full apply lays down, exactly. Written out rather than derived: this
# list is the contract compose.yml's bind mounts and composectl._CONSUMERS are
# both written against, and a silent addition to it is a file nothing reads.
EXPECTED_TREE = {
    "sing-box/00_base.json",
    "sing-box/90_outbounds.json",
    "sing-box/10_vless-reality.json",
    "sing-box/20_hysteria2.json",
    "sing-box/certs/certificate.pem",
    "sing-box/certs/private.key",
    "ikev2.env",
    "dnstt/server.key",
    "dnstt-sshd/logins",
    "dnstt.env",
}


def test_every_enabled_protocol_contributes(secrets, users) -> None:
    tree = render.build_tree(secrets, users, ALL)
    assert set(tree) == EXPECTED_TREE
    assert all(isinstance(v, bytes) for v in tree.values())


def test_the_untracked_half_comes_from_git(secrets, users) -> None:
    """The structural fragments are copied out of the checkout, not generated.

    Asserted as byte equality with the tracked file rather than by picking a key
    out of the JSON: the *values* in there -- the log level, the outbound set --
    belong to whoever edits those files, and a test that pins one turns an
    ordinary edit into a failure in a test about provenance. What must hold is
    that a clone can be diffed against what a server is serving.
    """
    tree = render.build_tree(secrets, users, ALL)
    for name in ("00_base.json", "90_outbounds.json"):
        assert tree[f"sing-box/{name}"] == (SING_BOX_COMMON / name).read_bytes()
    assert json.loads(tree["sing-box/00_base.json"])["log"]
    assert json.loads(tree["sing-box/90_outbounds.json"])["outbounds"]


def test_disabled_protocols_render_nothing(secrets, users) -> None:
    only_vless = protocols.ordered(["vless-reality"])
    tree = render.build_tree(secrets, users, only_vless)
    assert set(tree) == {
        "sing-box/00_base.json",
        "sing-box/90_outbounds.json",
        "sing-box/10_vless-reality.json",
    }


def test_a_disabled_user_appears_in_no_protocol(secrets, users) -> None:
    tree = render.build_tree(secrets, users, ALL)
    blob = b"".join(tree[k] for k in sorted(tree))
    assert b"bob" not in blob
    assert b"l2tp-bob" not in blob
    assert b"hy2-bob" not in blob
    assert b"alice" in blob


def test_two_protocols_writing_one_path_is_refused(secrets, users) -> None:
    # Nothing in the registry does this today; the check exists because a new
    # protocol module is one line away and the loser would be silently dropped.
    clash = Protocol(
        name="clash",
        kind=Kind.SINGBOX,
        order=99,
        ports=(Port(9999, "tcp"),),
        summary="",
        secret_names=(),
        default_enabled=False,
        render=lambda s, u: {"sing-box/10_vless-reality.json": b"{}"},
        share=lambda s, u, h: [],
        bootstrap=dict,
    )
    with pytest.raises(RenderError, match="would overwrite"):
        render.build_tree(secrets, users, [*ALL, clash])


def test_port_conflicts_are_caught_before_anything_renders(secrets, users) -> None:
    squatter = Protocol(
        name="squatter",
        kind=Kind.SINGBOX,
        order=99,
        ports=(Port(10443, "tcp"),),
        summary="",
        secret_names=(),
        default_enabled=False,
        render=lambda s, u: {"sing-box/99.json": b"{}"},
        share=lambda s, u, h: [],
        bootstrap=dict,
    )
    with pytest.raises(RenderError, match="port conflict"):
        render.build_tree(secrets, users, [*ALL, squatter])


def test_a_missing_secret_names_itself_and_the_file(users) -> None:
    with pytest.raises(MissingSecret) as excinfo:
        render.build_tree(secrets_store.Secrets(values={}), users, ALL)
    message = str(excinfo.value)
    assert "reality.key" in message
    assert "vpnctl bootstrap" in message


def test_build_tree_is_deterministic(secrets, users) -> None:
    assert render.build_tree(secrets, users, ALL) == render.build_tree(
        secrets, users, ALL
    )


def test_build_tree_writes_nothing(secrets, users, state_dir) -> None:
    render.build_tree(secrets, users, ALL)
    assert list(state_dir.iterdir()) == []


def test_every_rendered_file_is_0600(secrets, users, state_dir) -> None:
    """No rendered output is readable by anyone but root.

    The mode used to be chosen by filename -- 0600 for `.key` and `.env`, 0644
    for the rest -- and `dnstt-sshd/logins` ends in neither, so the plaintext
    list of every user's dnstt password was rendered world-readable, contained
    only by the 0700 parent directory. Asserting the property over the WHOLE
    tree rather than over a list of names is the point: a protocol that grows a
    new credential-bearing output cannot slip through by being unlisted.
    """
    candidate = render.write_candidate(render.build_tree(secrets, users, ALL))
    rendered = [p for p in candidate.rglob("*") if p.is_file()]
    assert rendered, "nothing was rendered, so this asserts nothing"
    wider = {
        str(p.relative_to(candidate)): oct(stat.S_IMODE(p.stat().st_mode))
        for p in rendered
        if stat.S_IMODE(p.stat().st_mode) != 0o600
    }
    assert wider == {}, f"rendered wider than 0600: {wider}"
    assert stat.S_IMODE(candidate.stat().st_mode) == 0o700


# --------------------------------- the impure half: candidate, promote, prune
#
# Untested until now, and the three functions that can lose the live tree. A bug
# in promote leaves `rendered` dangling and every container without a config on
# its next start; a bug in prune or write_candidate deletes a directory two
# running containers are bind-mounted to.


class _FrozenClock:
    """render's own `datetime`, stopped.

    The candidate name carries a UTC stamp at one-second resolution, so "two
    applies inside the same second" is the case that mattered and the case a
    wall-clock test cannot reproduce on purpose. Patched inside the module under
    test only, which is this suite's rule for anything impure.
    """

    @staticmethod
    def now(tz=None):
        return datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)


def a_tree(marker: str) -> dict[str, bytes]:
    return {"sing-box/10_vless-reality.json": marker.encode()}


def test_two_candidates_in_the_same_second_are_two_directories(
    monkeypatch, state_dir
) -> None:
    """The one that could delete the live tree.

    The name used to be exactly `rendered-<stamp>` and write_candidate did `if
    candidate.exists(): shutil.rmtree(candidate)` before rendering into it. Two
    applies inside the same second -- a scripted `user add` loop, or a deploy
    racing the boot unit's apply -- had the second one delete the tree the first
    had just promoted and that sing-box and dnstt-sshd were mounted from.
    """
    monkeypatch.setattr(render, "datetime", _FrozenClock)
    first = render.write_candidate(a_tree("first"))
    render.promote(first)
    second = render.write_candidate(a_tree("second"))

    assert first != second
    assert first.is_dir()
    assert (first / "sing-box/10_vless-reality.json").read_bytes() == b"first"
    assert (second / "sing-box/10_vless-reality.json").read_bytes() == b"second"
    # Still ordered by name and still matched by `rendered*`, which prune,
    # .gitignore and `vpn backup`'s tar exclude all rely on.
    assert first.name.startswith("rendered-20260925T120000Z-")
    assert second.name.startswith("rendered-20260925T120000Z-")


def test_a_candidate_directory_is_0700(state_dir) -> None:
    candidate = render.write_candidate(a_tree("x"))
    assert stat.S_IMODE(candidate.stat().st_mode) == 0o700


def test_the_live_tree_is_never_removed(state_dir) -> None:
    """The invariant, kept even though the naming scheme makes it unreachable.

    Removing the live tree does not fail loudly: the containers hold deleted
    inodes and serve until their next restart, then refuse to start, with the
    config they were serving gone from the disk.
    """
    candidate = render.write_candidate(a_tree("live"))
    render.promote(candidate)
    with pytest.raises(RenderError, match="live rendered tree"):
        render._rmtree_not_live(candidate)
    assert candidate.is_dir()


def test_promote_with_no_existing_link(state_dir) -> None:
    candidate = render.write_candidate(a_tree("first"))
    assert not RENDERED_LINK.exists()
    render.promote(candidate)
    assert RENDERED_LINK.is_symlink()
    assert RENDERED_LINK.resolve() == candidate
    # Relative, not absolute: the state directory has to survive being tarred up
    # by `vpn backup` and unpacked somewhere else by `vpn restore`.
    assert not os.path.isabs(os.readlink(RENDERED_LINK))


def test_promote_over_an_existing_link_keeps_the_old_tree_on_disk(state_dir) -> None:
    # The old generation is what `changed_services` diffs the next candidate
    # against, and what a human rolls back to by hand. promote must move a
    # symlink and nothing else.
    first = render.write_candidate(a_tree("first"))
    render.promote(first)
    second = render.write_candidate(a_tree("second"))
    render.promote(second)

    assert RENDERED_LINK.resolve() == second
    assert (RENDERED_LINK / "sing-box/10_vless-reality.json").read_bytes() == b"second"
    assert first.is_dir()
    assert (first / "sing-box/10_vless-reality.json").read_bytes() == b"first"


def test_promote_survives_a_leftover_temporary_link(state_dir) -> None:
    # `.rendered.new` is left behind by a promote killed between symlink_to and
    # os.replace. Without the unlink, symlink_to raises FileExistsError and every
    # apply after that crash fails -- on a server whose live tree is fine.
    first = render.write_candidate(a_tree("first"))
    leftover = state_dir / ".rendered.new"
    leftover.symlink_to("rendered-does-not-exist")
    render.promote(first)
    assert RENDERED_LINK.resolve() == first
    assert not leftover.exists() and not leftover.is_symlink()


def generations(state_dir, names: list[str]) -> list[Path]:
    made = []
    for name in names:
        path = state_dir / name
        path.mkdir()
        (path / "marker").write_text(name)
        made.append(path)
    return made


NAMES = [f"rendered-2026092{d}T120000Z-aaaaaa" for d in range(1, 8)]


def test_prune_keeps_the_newest_five(state_dir) -> None:
    made = generations(state_dir, NAMES)
    removed = render.prune()
    assert sorted(removed) == sorted(made[:2])
    survivors = sorted(p.name for p in state_dir.glob("rendered-*"))
    assert survivors == sorted(n for n in NAMES[2:])


def test_prune_keeps_the_live_generation_however_old_it_is(state_dir) -> None:
    """Age is not the criterion, `rendered` is.

    `apply --no-restart` and `bootstrap --force` promote without converging, and
    a box can then sit for many applies on a tree that is no longer the newest --
    pruning it by age would delete the config the containers are mounted from.
    """
    made = generations(state_dir, NAMES)
    oldest = made[0]
    render.promote(oldest)

    removed = render.prune()
    assert oldest.is_dir()
    assert oldest not in removed
    assert RENDERED_LINK.resolve() == oldest
    # Still only two go: the live one is kept in addition to the newest five.
    assert sorted(removed) == [made[1]]


def test_prune_with_fewer_generations_than_it_keeps_removes_nothing(state_dir) -> None:
    generations(state_dir, NAMES[:3])
    assert render.prune() == []


def test_prune_ignores_a_file_that_merely_matches_the_glob(state_dir) -> None:
    # `vpn backup` writes nothing here, but a half-unpacked restore can leave a
    # stray file; prune must not try to rmtree it.
    generations(state_dir, NAMES)
    (state_dir / "rendered-stray.tgz").write_text("x")
    render.prune()
    assert (state_dir / "rendered-stray.tgz").exists()
