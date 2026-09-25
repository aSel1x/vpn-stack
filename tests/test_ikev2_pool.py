"""The XAUTH pool parse: the value that goes straight to iptables.

This is the parse whose history is "a plausible constant that was wrong". It
said 192.168.42.0/24 -- the L2TP pool -- while ikev2.sh hands IKEv2 clients
addresses from the XAUTH pool, so every FORWARD rule vpnctl installed protected
addresses no client is ever given, and both health checks asserted that same
constant and reported green in the one failure they exist to catch. It has three
near-identical implementations (here, scripts/smoke.sh, scripts/diagnose-ikev2.sh)
and had no test at all.

Everything here runs against real ikev2.conf text with no container anywhere,
which is the whole reason the parse was split out of the two docker execs.
"""

from __future__ import annotations

from vpnctl import ikev2ctl

# Verbatim in shape from a stock hwdsl2/ipsec-vpn-server: one `conn ikev2-cp`,
# one rightaddresspool, dual-stack, and the IPv4 half is a range and not a CIDR.
IKEV2_CONF = """conn ikev2-cp
  left=%defaultroute
  leftid=@vpn.example.com
  leftcert=vpn.example.com
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  leftrsasigkey=%cert
  right=%any
  rightid=%fromcert
  rightaddresspool=192.168.43.10-192.168.43.250,fddd:500:500:500::1000-fddd:500:500:500::9999
  rightca=%same
  rightrsasigkey=%cert
  narrowing=yes
  dpddelay=30
  dpdtimeout=120
  auto=add
"""


def test_the_stock_dual_stack_pool_gives_the_xauth_slash_24() -> None:
    net, provenance = ikev2ctl.pool_network(IKEV2_CONF, None)
    assert net == "192.168.43.0/24"
    assert provenance == "conn ikev2-cp rightaddresspool"


def test_the_l2tp_subnet_never_comes_out_of_a_stock_conf() -> None:
    # The regression in one line: 192.168.42.0/24 is what this used to say, and
    # it is a real subnet on the same box -- so the wrong answer looks right to
    # anybody who does not already know which pool is which.
    assert ikev2ctl.pool_network(IKEV2_CONF, None)[0] != "192.168.42.0/24"


def test_a_pool_wider_than_a_slash_24_is_covered_whole() -> None:
    # Assuming a /24 on the FIRST address left every client above the boundary
    # outside every rule and outside every check: green, carrying nothing. The
    # covering network is wider than the pool, which is the safe direction --
    # the extra addresses are ones pluto never assigns.
    net, provenance = ikev2ctl.pool_network(
        "  rightaddresspool=192.168.43.10-192.168.44.250\n", None
    )
    assert net == "192.168.40.0/21"
    assert provenance == "conn ikev2-cp rightaddresspool"
    assert ikev2ctl._covering_net("192.168.43.10-192.168.44.250") == net


def test_a_cidr_pool_is_read_as_one() -> None:
    assert ikev2ctl.pool_network("rightaddresspool=192.168.43.0/24", None) == (
        "192.168.43.0/24",
        "conn ikev2-cp rightaddresspool",
    )


def test_an_ipv6_only_pool_falls_through_and_says_so() -> None:
    # IKEv2 over IPv6 is out of scope (ensure_ipv4_forwarding says so), so the
    # answer is the default -- which happens to equal the stock /24. The
    # provenance is the only thing that distinguishes "measured" from "guessed",
    # which is exactly why it is returned beside the network.
    conf = IKEV2_CONF.replace(
        "rightaddresspool=192.168.43.10-192.168.43.250,"
        "fddd:500:500:500::1000-fddd:500:500:500::9999",
        "rightaddresspool=fddd:500:500:500::1000-fddd:500:500:500::9999",
    )
    net, provenance = ikev2ctl.pool_network(conf, None)
    assert net == "192.168.43.0/24"
    assert provenance == "image default -- conn ikev2-cp offers no IPv4 pool"


def test_a_conf_without_a_pool_is_not_a_conf_we_can_use() -> None:
    net, provenance = ikev2ctl.pool_network(
        "conn ikev2-cp\n  left=%defaultroute\n", None
    )
    assert net == "192.168.43.0/24"
    assert provenance == "image default -- ikev2.conf names no rightaddresspool"


def test_vpn_xauth_net_is_the_fallback_and_is_normalised() -> None:
    # Host bits included, the way the shell copies normalise it too:
    # 192.168.77.10/24 -> 192.168.77.0/24.
    assert ikev2ctl.pool_network(None, "192.168.77.10/24\n") == (
        "192.168.77.0/24",
        "VPN_XAUTH_NET",
    )


def test_the_pool_wins_over_vpn_xauth_net() -> None:
    # run.sh uses VPN_XAUTH_NET for its firewall rules while ikev2.sh builds the
    # pool from VPN_XAUTH_POOL, so the two can be set apart. Preferring the net
    # would reproduce the original bug for anyone who set only one of them.
    net, provenance = ikev2ctl.pool_network(IKEV2_CONF, "192.168.77.0/24")
    assert net == "192.168.43.0/24"
    assert provenance == "conn ikev2-cp rightaddresspool"


def test_an_unparseable_xauth_net_is_refused_rather_than_handed_to_iptables() -> None:
    # "192.168.256.0/24" matches every shape-only regex and is not an address.
    # Handed to `iptables -C` it fails in a way indistinguishable from "the rule
    # is missing", which reports a healthy box as broken.
    net, provenance = ikev2ctl.pool_network(None, "192.168.256.0/24")
    assert net == "192.168.43.0/24"
    assert "does not parse" in provenance
    assert provenance.startswith("image default -- ")


def test_an_ipv6_xauth_net_is_not_an_ipv4_answer() -> None:
    net, provenance = ikev2ctl.pool_network(None, "fddd:500:500:500::/64")
    assert net == "192.168.43.0/24"
    assert provenance == (
        "image default -- VPN_XAUTH_NET='fddd:500:500:500::/64' is not IPv4"
    )


def test_a_silent_container_reaches_the_default_with_that_provenance() -> None:
    # The case the provenance exists for: nothing answered, so the network is a
    # constant from the image's README and not an observation of this server.
    assert ikev2ctl.pool_network(None, None) == (
        "192.168.43.0/24",
        "image default -- container config unreadable",
    )
