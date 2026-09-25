"""protocols.assert_ports_disjoint.

`sing-box check` exits 0 on two inbounds sharing a listen_port -- verified
against the real binary; it catches a duplicate *tag*, not a duplicate port. So
this function is the only thing between `protocol on` and a config that
validates, deploys, and then half-works.
"""

from __future__ import annotations

import pytest

from vpnctl import protocols, render
from vpnctl.protocols import Kind, Port, Protocol, RenderError
from vpnctl.secrets_store import Secrets


def _proto(name: str, *ports: Port, render=lambda s, u: {}) -> Protocol:
    return Protocol(
        name=name,
        kind=Kind.SINGBOX,
        order=99,
        ports=ports,
        summary="",
        secret_names=(),
        default_enabled=False,
        render=render,
        share=lambda s, u, h: [],
        bootstrap=dict,
    )


def test_the_real_registry_is_disjoint() -> None:
    protocols.assert_ports_disjoint(protocols.ordered())


def test_the_registry_claims_the_ports_documented_in_claude_md() -> None:
    claimed = {str(p) for proto in protocols.ordered() for p in proto.ports}
    assert claimed == {
        "10443/tcp",
        "20443/udp",
        "500/udp",
        "4500/udp",
        "1701/udp",
        "53/udp",
    }


def test_nothing_enabled_is_fine() -> None:
    protocols.assert_ports_disjoint([])


def test_two_protocols_on_one_port_is_refused() -> None:
    a, b = _proto("a", Port(443, "tcp")), _proto("b", Port(443, "tcp"))
    with pytest.raises(RenderError) as excinfo:
        protocols.assert_ports_disjoint([a, b])
    message = str(excinfo.value)
    assert "443/tcp" in message
    # Both names, because the operator has to know what to turn off.
    assert "a" in message and "b" in message


def test_the_transport_is_part_of_the_key() -> None:
    # 53/tcp and 53/udp are different sockets; refusing this pair would block a
    # legitimate combination.
    pair = [_proto("a", Port(53, "udp")), _proto("b", Port(53, "tcp"))]
    protocols.assert_ports_disjoint(pair)
    # The same case against the real registry rather than two fixtures, because
    # the one number this is ever going to matter for is dnstt's 53: a future
    # DNS-over-TCP sibling must not be refused on the strength of the digits.
    protocols.assert_ports_disjoint(
        [*protocols.ordered(), _proto("t", Port(53, "tcp"))]
    )
    # And the mirror image, so the pair above is proof of the transport mattering
    # rather than of the check being asleep.
    with pytest.raises(RenderError, match="53/udp"):
        protocols.assert_ports_disjoint(
            [*protocols.ordered(), _proto("u", Port(53, "udp"))]
        )


def test_a_protocol_colliding_with_itself_is_refused() -> None:
    with pytest.raises(RenderError, match="port conflict"):
        protocols.assert_ports_disjoint(
            [_proto("a", Port(500, "udp"), Port(500, "udp"))]
        )


def test_it_runs_before_anything_is_rendered() -> None:
    # build_tree calls it first; a conflicting pair must never reach render().
    def explode(secrets, users):
        raise AssertionError("render() ran despite a port conflict")

    clash = _proto("clash", Port(10443, "tcp"), render=explode)
    with pytest.raises(RenderError, match="port conflict"):
        render.build_tree(Secrets(values={}), [], [*protocols.ordered(), clash])
