"""The protocol registry.

One module per protocol, each exporting a single `Protocol`. Everything the
rest of the system needs to know about a protocol -- which ports it claims,
which secrets it needs, how to render its config, how to build a client's
share link, whether it is a sing-box inbound or its own container -- lives
there and nowhere else.

Adding a protocol is a new module plus one line in PROTOCOLS. It changes no
command line: the `-C` directory list that used to be hardcoded in compose.yml,
sbctl.py and deploy.yml is gone, replaced by a single rendered directory.

`render` and `share` are pure: no open(), no subprocess, no globals. That is
deliberate and load-bearing -- it is the seam a future GUI app renders share
links through without a server round-trip.

sing-box's log level lives in sing-box/common/00_base.json and is `warn`. The
reason is written here because JSON has nowhere to put it, and because this is
the file a reader of the registry actually opens. At `info` sing-box logs every
connection with the authenticated user name beside the client's source address
and the destination host, so the rolling 10m x 3 json-file log compose gives
that container becomes a standing record correlating person <-> residential IP
<-> site visited -- the exact record this stack exists so that nobody else can
build, produced by a default nobody chose. What `warn` gives up is real and is
the operator's decision, made knowingly: a client that cannot connect now
leaves almost nothing behind, so `./vpn logs sing-box` is thin and a handshake
failure is diagnosed from the client's side or by raising the level for the
length of one test. Nothing machine-readable depends on those lines -- neither
vpnctl nor scripts/smoke.sh parses sing-box's output; both assert on bound
ports -- so the level is free to be chosen for privacy alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping

from vpnctl.secrets_store import Secrets
from vpnctl.users_store import User


class Kind(Enum):
    SINGBOX = "singbox"  # an inbound merged into the sing-box config tree
    COMPOSE = "compose"  # its own container, toggled by compose profile


@dataclass(frozen=True)
class Port:
    number: int
    proto: str  # "tcp" | "udp"

    def __str__(self) -> str:
        return f"{self.number}/{self.proto}"


@dataclass(frozen=True)
class ShareItem:
    """One deliverable for one user. Exactly one of three shapes:

      uri      something a client imports or a QR code carries
      filename a file to install, with `content`
      fields   settings typed into a form by hand

    The third exists because DNSTT-over-SSH has no import format at all: the
    apps have a form, and that is the whole interface. Dressing those settings
    up as a `uri` made every layer treat them as one -- a QR code nothing can
    scan, a tappable link that imports nothing.

    The `filename` shape has no producer in the pure layer today and is kept
    anyway: IKEv2's bundles already travel as filename/label/b64, which the app
    parses, and they only bypass this class because ikev2.sh makes them inside
    the container. What it does not have is a *consumer*: cli.cmd_user_export
    prints `uri`, then `fields`, and drops anything else without a word. So a
    protocol that starts returning a filename-shaped item has to add that branch
    in the same change, or `user export` reports ok while the one file the
    recipient needed is simply absent from the payload.
    """

    label: str  # human name, e.g. "iOS/macOS"
    filename: str | None  # set for files, None otherwise
    uri: str | None  # set for URIs, None otherwise
    content: bytes | None = None
    fields: tuple[tuple[str, str], ...] = ()  # (setting, value), in order

    def __post_init__(self) -> None:
        """Exactly one shape, refused where it is built rather than where it is shown.

        Every layer above branches on which field is set, and the branches are
        ordered -- cli.cmd_user_export tests `uri` first -- so an item in two
        shapes is not ambiguous in theory, it is silently the wrong one of the
        two. An item in no shape is a labelled empty row on somebody's share
        page. Both are programming errors in a protocol module, and the whole
        point of catching them here is that the traceback names the module
        instead of the renderer.
        """
        shapes = (bool(self.uri), bool(self.filename), bool(self.fields))
        if sum(shapes) != 1:
            raise RenderError(
                f"share item {self.label!r} must set exactly one of uri, "
                "filename or fields"
            )
        if self.filename and self.content is None:
            raise RenderError(
                f"share item {self.label!r} names a file but carries no content"
            )


@dataclass(frozen=True)
class Protocol:
    name: str
    kind: Kind
    order: int
    ports: tuple[Port, ...]
    summary: str
    secret_names: tuple[str, ...]
    default_enabled: bool
    render: Callable[[Secrets, list[User]], dict[str, bytes]]
    share: Callable[[Secrets, User, str], list[ShareItem]]
    bootstrap: Callable[[], dict[str, bytes]]
    compose_profile: str | None = None
    compose_services: tuple[str, ...] = ()
    notes: str = ""
    # IKEv2 client bundles are produced by ikev2.sh inside the container, so
    # unlike every other protocol its share() cannot be a pure function of the
    # keyring. Flagged here rather than special-cased by name in the CLI.
    share_via_container: bool = False
    # Does this protocol issue a distinct credential per user? dnstt does not:
    # it is one tunnel with one login. This governs provisioning, NOT sharing
    # -- everyone still needs the connection parameters, and filtering export
    # on it meant `user export` silently returned nothing for dnstt.
    per_user: bool = True
    # Secrets that pure Python cannot produce. dnstt's Noise keypair is emitted
    # by the dnstt-server binary itself, which means building a Go image -- too
    # expensive to do in `bootstrap` for a protocol that ships disabled. Run
    # once, at `protocol on`, which is the moment you agreed to pay for it.
    prepare: Callable[[], dict[str, bytes]] | None = None
    # Bootstrap outputs that can be REBUILT from the ones that survived, as
    # {secret name: function of the surviving keyring}. bootstrap refuses to top
    # up a half-present set because filling a gap pairs a fresh half with a
    # stale survivor -- which renders, serves, and fails on every client. A
    # derived half is not a fresh one: it is the same key's other face, so it is
    # the one gap that can be filled without invalidating a profile already
    # handed out. It lives here, beside the bootstrap() that mints the pair,
    # because a second copy of the derivation in bootstrap.py is a second thing
    # that can disagree with this one.
    derivable: Mapping[str, Callable[[Secrets], bytes]] | None = None


class RenderError(RuntimeError):
    pass


def _load_registry() -> dict[str, Protocol]:
    from vpnctl.protocols import dnstt, hysteria2, ikev2, vless_reality

    return {
        p.name: p
        for p in (
            vless_reality.PROTOCOL,
            hysteria2.PROTOCOL,
            ikev2.PROTOCOL,
            dnstt.PROTOCOL,
        )
    }


PROTOCOLS: dict[str, Protocol] = _load_registry()


def get(name: str) -> Protocol:
    try:
        return PROTOCOLS[name]
    except KeyError:
        known = ", ".join(sorted(PROTOCOLS))
        raise RenderError(f"unknown protocol {name!r}; known: {known}") from None


def ordered(names: list[str] | None = None) -> list[Protocol]:
    chosen = PROTOCOLS.values() if names is None else [get(n) for n in names]
    return sorted(chosen, key=lambda p: p.order)


def assert_ports_disjoint(enabled: list[Protocol]) -> None:
    """Two inbounds on one port is not an error sing-box will catch.

    Verified against the real binary: `sing-box check` exits 0 with two
    inbounds bound to the same listen_port. It does catch a duplicate tag.
    So the registry has to own this check itself, or `protocol on` can produce
    a config that validates and then half-works at runtime.
    """
    seen: dict[str, str] = {}
    for proto in enabled:
        for port in proto.ports:
            key = str(port)
            if key in seen:
                raise RenderError(
                    f"port conflict: {proto.name} and {seen[key]} both claim {key}"
                )
            seen[key] = proto.name
