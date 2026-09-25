"""dotenv.read -- the half of `.env` parsing that must agree with compose.

Both programs read /etc/vpn-stack/.env. compose interpolates
`${VPN_DNSTT_ZONE}` into the dnstt server's command line; this reader feeds the
same value into share links and into `protocol on dnstt`'s refusal. A
disagreement is silent on both sides: the container serves one zone, the QR card
in somebody's hand names another, and each half looks correct on its own.
"""

from __future__ import annotations

from pathlib import Path

from vpnctl.dotenv import read


def env(tmp_path: Path, body: str) -> dict[str, str]:
    path = tmp_path / ".env"
    path.write_text(body)
    return read(path)


def test_a_missing_file_is_no_values(tmp_path: Path) -> None:
    assert read(tmp_path / "nothing-here") == {}


def test_an_unquoted_value(tmp_path: Path) -> None:
    assert env(tmp_path, "VPN_DNSTT_ZONE=tun.example.com\n") == {
        "VPN_DNSTT_ZONE": "tun.example.com"
    }


def test_double_quotes_are_stripped_because_compose_strips_them(tmp_path: Path) -> None:
    # Keeping them handed every client the literal `"tun.example.com"` while the
    # container was serving tun.example.com -- from a file the operator had
    # filled in correctly.
    assert env(tmp_path, 'VPN_DNSTT_ZONE="tun.example.com"\n') == {
        "VPN_DNSTT_ZONE": "tun.example.com"
    }


def test_single_quotes_are_stripped_too(tmp_path: Path) -> None:
    assert env(tmp_path, "VPN_SERVER_HOST='198.51.100.7'\n") == {
        "VPN_SERVER_HOST": "198.51.100.7"
    }


def test_a_mismatched_quote_is_data(tmp_path: Path) -> None:
    # compose leaves it alone, so this must too: stripping one side would invent
    # a value nobody wrote.
    assert env(tmp_path, 'VPN_SERVER_HOST="198.51.100.7\n')["VPN_SERVER_HOST"] == (
        '"198.51.100.7'
    )
    assert env(tmp_path, "K=it's\n")["K"] == "it's"


def test_an_empty_value_and_an_empty_quoted_value(tmp_path: Path) -> None:
    assert env(tmp_path, 'A=\nB=""\n') == {"A": "", "B": ""}


def test_only_the_first_equals_splits(tmp_path: Path) -> None:
    # Passwords and base64 land in .env; an '=' in the value is ordinary.
    assert env(tmp_path, "K=a=b=c\n") == {"K": "a=b=c"}


def test_a_trailing_comment_is_not_stripped(tmp_path: Path) -> None:
    """Deliberate, and depended on elsewhere.

    compose does not strip a trailing comment from a value either, and
    scripts/provision-host.sh states that where it writes the commented
    `#VPN_DNSTT_ZONE=` hint into a fresh .env -- so uncommenting the line below
    its own explanatory comment cannot silently set the zone to that comment.
    That note is only true while this reader stays literal.
    """
    assert env(tmp_path, "VPN_DNSTT_ZONE=tun.example.com # the zone\n") == {
        "VPN_DNSTT_ZONE": "tun.example.com # the zone"
    }


def test_blank_lines_and_comments_are_skipped(tmp_path: Path) -> None:
    body = "\n# dnstt only, and there is no default.\n#VPN_DNSTT_ZONE=tun.example.com\n\nA=1\n   \n"
    assert env(tmp_path, body) == {"A": "1"}


def test_export_is_accepted(tmp_path: Path) -> None:
    # What an operator who has edited a shell profile writes, and compose takes
    # it; treating `export VPN_DNSTT_ZONE` as the key meant the value was simply
    # never found and dnstt looked unconfigured.
    assert env(tmp_path, 'export VPN_DNSTT_ZONE="tun.example.com"\n') == {
        "VPN_DNSTT_ZONE": "tun.example.com"
    }
    assert env(tmp_path, "export\tA=1\n") == {"A": "1"}


def test_a_key_named_export_is_still_a_key(tmp_path: Path) -> None:
    # The prefix is a word followed by whitespace, not the letters "export".
    assert env(tmp_path, "exported=yes\n") == {"exported": "yes"}


def test_a_later_line_wins(tmp_path: Path) -> None:
    assert env(tmp_path, "A=1\nA=2\n") == {"A": "2"}


def test_whitespace_around_the_key_and_value_goes(tmp_path: Path) -> None:
    assert env(tmp_path, "  A = 1  \n") == {"A": "1"}
