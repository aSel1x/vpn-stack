"""firewall.reconcile -- the diff, not the ufw binary.

Only two things are faked, both named here: `available()`, which shells out to
`which ufw`, and `_ufw()`, the single wrapper every ufw call goes through. The
parsing, the diff and the 22/tcp invariant are the real code.
"""

from __future__ import annotations

import pytest

from vpnctl import firewall, protocols

# Real `ufw status` output, including the shapes that must NOT be picked up: a
# rule somebody added by hand, a rule with a comment that is not ours, and the
# (v6) duplicates ufw prints for every rule.
STATUS = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere                   # vpn-stack:ssh
10443/tcp                  ALLOW       Anywhere                   # vpn-stack:vless-reality
53/udp                     ALLOW       Anywhere                   # vpn-stack:dnstt
443/tcp                    ALLOW       Anywhere
8080/tcp                   ALLOW       Anywhere                   # grafana, by hand
22/tcp (v6)                ALLOW       Anywhere (v6)              # vpn-stack:ssh
10443/tcp (v6)             ALLOW       Anywhere (v6)              # vpn-stack:vless-reality
"""


class FakeUfw:
    """Stands in for the ufw binary. `status` answers; mutations are recorded."""

    def __init__(self, status: str = STATUS) -> None:
        self.status = status
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str) -> tuple[bool, str]:
        self.calls.append(args)
        return True, self.status if args == ("status",) else ""

    @property
    def mutations(self) -> list[tuple[str, ...]]:
        return [c for c in self.calls if c != ("status",)]


@pytest.fixture
def ufw(monkeypatch) -> FakeUfw:
    fake = FakeUfw()
    monkeypatch.setattr(firewall, "available", lambda: True)
    monkeypatch.setattr(firewall, "_ufw", fake)
    return fake


def test_only_tagged_rules_are_seen(ufw) -> None:
    assert firewall.current_tagged() == {
        "22/tcp": "ssh",
        "10443/tcp": "vless-reality",
        "53/udp": "dnstt",
    }
    # 443/tcp has no comment and 8080/tcp has somebody else's. Neither is ours
    # to delete, and neither is ours to count as present.
    assert "443/tcp" not in firewall.current_tagged()
    assert "8080/tcp" not in firewall.current_tagged()


def test_the_v6_duplicate_lines_do_not_become_separate_rules(ufw) -> None:
    # `22/tcp (v6)` does not match: the parser wants ALLOW right after the
    # port. `ufw allow 22/tcp` covers both families anyway.
    assert list(firewall.current_tagged()) == ["22/tcp", "10443/tcp", "53/udp"]


def test_desired_comes_straight_from_the_registry() -> None:
    assert firewall.desired(protocols.ordered()) == {
        "10443/tcp": "vless-reality",
        "20443/udp": "hysteria2",
        "500/udp": "ikev2",
        "4500/udp": "ikev2",
        "1701/udp": "ikev2",
        "53/udp": "dnstt",
    }


def test_the_diff_adds_what_is_missing_and_removes_what_is_ours(ufw) -> None:
    enabled = protocols.ordered(["vless-reality", "hysteria2"])
    ok, actions = firewall.reconcile(enabled)
    assert ok
    assert actions == [
        "+ allow 20443/udp (hysteria2)",
        f"! refusing to remove {firewall.SSH_RULE} (invariant)",
        "- delete 53/udp (was dnstt)",
    ]
    assert ufw.mutations == [
        ("allow", "20443/udp", "comment", "vpn-stack:hysteria2"),
        ("--force", "delete", "allow", "53/udp"),
    ]


def test_22_tcp_is_never_removed(ufw) -> None:
    """A hard invariant: the only way to fix a mistake here is through it.

    22/tcp is tagged `vpn-stack:ssh` and no protocol claims it, so every
    reconcile sees it as a rule of ours that is no longer wanted.
    """
    ok, actions = firewall.reconcile(protocols.ordered())
    assert ok
    assert f"! refusing to remove {firewall.SSH_RULE} (invariant)" in actions
    assert all("22/tcp" not in " ".join(call) for call in ufw.mutations)


def test_nothing_a_human_added_is_ever_touched(ufw) -> None:
    firewall.reconcile(protocols.ordered(["vless-reality"]))
    flat = [" ".join(call) for call in ufw.mutations]
    assert not any("443/tcp" in c or "8080/tcp" in c for c in flat)


def test_dry_run_reports_the_same_diff_and_changes_nothing(ufw) -> None:
    enabled = protocols.ordered(["vless-reality", "hysteria2"])
    _, planned = firewall.reconcile(enabled, dry_run=True)
    assert ufw.mutations == []
    _, done = firewall.reconcile(enabled)
    assert planned == done


def test_an_already_matching_firewall_says_so(ufw) -> None:
    ufw.status = """Status: active

To                         Action      From
--                         ------      ----
10443/tcp                  ALLOW       Anywhere                   # vpn-stack:vless-reality
"""
    ok, actions = firewall.reconcile(protocols.ordered(["vless-reality"]))
    assert (ok, actions) == (True, ["firewall already matches the enabled set"])
    assert ufw.mutations == []


def test_a_failing_ufw_stops_at_the_first_error(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def failing(*args: str) -> tuple[bool, str]:
        calls.append(args)
        if args == ("status",):
            return True, STATUS
        return False, "ERROR: Bad port"

    monkeypatch.setattr(firewall, "available", lambda: True)
    monkeypatch.setattr(firewall, "_ufw", failing)
    ok, actions = firewall.reconcile(protocols.ordered())
    assert not ok
    assert actions[-1].startswith("FAILED:")
    # One mutation attempted, then stop -- not a loop that reports every failure
    # while carrying on changing the firewall.
    assert len([c for c in calls if c != ("status",)]) == 1


def test_no_ufw_is_not_a_failure(monkeypatch) -> None:
    monkeypatch.setattr(firewall, "available", lambda: False)
    monkeypatch.setattr(
        firewall, "_ufw", lambda *a: pytest.fail("ufw called when unavailable")
    )
    ok, actions = firewall.reconcile(protocols.ordered())
    assert ok
    assert "skipping" in actions[0]


def test_an_unreadable_status_adds_rather_than_deletes(monkeypatch) -> None:
    # `ufw status` needs root; without it current_tagged() returns {}. The
    # consequence is re-adding rules ufw will dedupe, never deleting live ones.
    monkeypatch.setattr(firewall, "available", lambda: True)
    fake = FakeUfw()
    monkeypatch.setattr(
        firewall,
        "_ufw",
        lambda *a: (False, "need root") if a == ("status",) else fake(*a),
    )
    ok, actions = firewall.reconcile(protocols.ordered(["vless-reality"]))
    assert ok
    assert actions == ["+ allow 10443/tcp (vless-reality)"]
