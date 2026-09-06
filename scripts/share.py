#!/usr/bin/env python3
"""One-shot credential handoff over the local network.

Reads `vpnctl --json user export` on stdin, serves it once to one device on
your LAN, and dies. Exists because a QR code cannot carry a .mobileconfig,
and scp-ing one to a phone is the workflow this replaces.

Design constraints, each for a reason:

  * Binds an RFC1918 address only, and refuses a public one outright. This
    page hands out live credentials; it must not be reachable from anywhere
    that isn't already inside your network.
  * Runs on YOUR machine, not the server. The VPN box gains no listener, no
    certificate in Certificate Transparency, and no new attack surface -- which
    is the whole reason a public claim service was rejected.
  * Single-use, unguessable path. Burns 120s after the page is first fetched
    (assets need that grace window) or after 10 minutes, whichever is first.
    Single-use doubles as a tripwire: if the recipient says the link was
    already used, someone else on that network read it.
  * .mobileconfig is served as application/x-apple-aspen-config, which is what
    makes iOS Safari offer it straight to Settings instead of showing XML.

The transport is plain HTTP and that is a deliberate, bounded trade: a
self-signed cert trains people to click through a warning on a page that then
installs a configuration profile, and iOS will not install a .mobileconfig from
a blob: URL, so browser-side decryption cannot cover the one thing this exists
for. The mitigation is the short window, the single use, and the LAN-only bind
-- plus a warning printed every time.
"""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import secrets
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GRACE_AFTER_FETCH = 120.0
HARD_TIMEOUT = 600.0

CONTENT_TYPES = {
    ".mobileconfig": "application/x-apple-aspen-config",
    ".p12": "application/x-pkcs12",
    ".sswan": "application/octet-stream",
    ".png": "image/png",
}


def local_addresses() -> list[str]:
    """Every RFC1918/link-local address on this machine."""
    found: list[str] = []
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        addr = info[4][0]
        if addr not in found:
            found.append(addr)
    # getaddrinfo misses interfaces on some setups; ask the routing table too.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.168.255.255", 9))
        addr = probe.getsockname()[0]
        probe.close()
        if addr not in found:
            found.insert(0, addr)
    except OSError:
        pass
    return [a for a in found if ipaddress.ip_address(a).is_private]


def pick_bind(explicit: str | None) -> str:
    if explicit:
        if not ipaddress.ip_address(explicit).is_private:
            raise SystemExit(
                f"refusing to bind {explicit}: not a private address.\n"
                "This page serves live credentials and must stay on your LAN."
            )
        return explicit
    candidates = local_addresses()
    if not candidates:
        raise SystemExit(
            "no private (RFC1918) address found on this machine.\n"
            "Connect to the same network as the device, or pass --bind <addr>."
        )
    return candidates[0]


class Bundle:
    """The share payload, flattened into what the page needs."""

    def __init__(self, payload: dict):
        self.user: str = payload.get("user", "user")
        self.uris: list[tuple[str, str]] = []      # (label, uri)
        self.files: dict[str, tuple[str, bytes]] = {}  # filename -> (label, bytes)
        self.qr: dict[str, bytes] = {}             # label -> png
        # Settings typed into a form by hand. DNSTT-over-SSH has no import
        # format, so this is the only shape that is honest about it.
        self.forms: list[tuple[str, list[tuple[str, str]]]] = []

        for proto, items in (payload.get("protocols") or {}).items():
            for item in items:
                label = item.get("label") or proto
                if item.get("uri"):
                    self.uris.append((f"{proto} — {label}", item["uri"]))
                    if item.get("png_b64"):
                        self.qr[f"{proto} — {label}"] = base64.b64decode(item["png_b64"])
                elif item.get("fields"):
                    self.forms.append(
                        (f"{proto} — {label}", [(k, v) for k, v in item["fields"]])
                    )
                elif item.get("filename") and item.get("b64"):
                    self.files[item["filename"]] = (label, base64.b64decode(item["b64"]))

    def empty(self) -> bool:
        return not self.uris and not self.files and not self.forms


PAGE = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{user} — VPN</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         margin: 0; padding: 1.5rem 1.25rem 4rem; max-width: 34rem; }}
  h1 {{ font-size: 1.3rem; margin: 0 0 .3rem; }}
  p.sub {{ margin: 0 0 1.75rem; opacity: .65; font-size: .9rem; }}
  h2 {{ font-size: .78rem; text-transform: uppercase; letter-spacing: .09em;
       opacity: .55; margin: 2rem 0 .75rem; font-weight: 600; }}
  a.item {{ display: block; padding: .85rem 1rem; margin-bottom: .5rem;
           border: 1px solid rgba(128,128,128,.35); border-radius: 10px;
           text-decoration: none; color: inherit; }}
  a.item b {{ display: block; font-size: .95rem; }}
  a.item span {{ display: block; font-size: .78rem; opacity: .6; margin-top: .15rem;
                word-break: break-all; }}
  table.form {{ width: 100%; border-collapse: collapse; margin-bottom: 1.25rem;
               font-size: .85rem; }}
  table.form th {{ text-align: left; font-weight: 500; opacity: .6;
                  padding: .45rem .6rem .45rem 0; vertical-align: top;
                  white-space: nowrap; }}
  table.form td {{ padding: .45rem 0; word-break: break-all;
                  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  table.form tr + tr {{ border-top: 1px solid rgba(128,128,128,.2); }}
  h3.form {{ font-size: .9rem; margin: 1.5rem 0 .4rem; }}
  .warn {{ font-size: .8rem; opacity: .6; margin-top: 2.5rem;
          border-top: 1px solid rgba(128,128,128,.3); padding-top: 1rem; }}
</style>
<h1>{user}</h1>
<p class="sub">Tap to import. This page works once and then disappears.</p>
{body}
<p class="warn">Sent over your local network only. Once you have imported these,
the link is dead — ask for a new one if you need it again.</p>
"""


def render_page(bundle: Bundle, token: str) -> bytes:
    parts: list[str] = []
    if bundle.uris:
        parts.append("<h2>Proxy profiles</h2>")
        for label, uri in bundle.uris:
            parts.append(
                f'<a class="item" href="{html.escape(uri, quote=True)}">'
                f"<b>{html.escape(label)}</b>"
                f"<span>{html.escape(uri[:80])}…</span></a>"
            )
    if bundle.forms:
        parts.append("<h2>Type these in by hand</h2>")
        for title, rows in bundle.forms:
            parts.append(f"<h3 class=\"form\">{html.escape(title)}</h3><table class=\"form\">")
            for key, value in rows:
                parts.append(
                    f"<tr><th>{html.escape(key)}</th>"
                    f"<td>{html.escape(value)}</td></tr>"
                )
            parts.append("</table>")
    if bundle.files:
        parts.append("<h2>Install profiles</h2>")
        for filename, (label, blob) in bundle.files.items():
            # Verified against the live image: ikev2.sh exports PKCS#12 with an
            # EMPTY password. Say so, or the recipient hunts for one that does
            # not exist -- and know that the file is an unprotected private key.
            hint = " · no password" if filename.endswith(".p12") else ""
            parts.append(
                f'<a class="item" href="/{token}/{html.escape(filename, quote=True)}">'
                f"<b>{html.escape(label)}</b>"
                f"<span>{html.escape(filename)} · {len(blob) // 1024 or 1} KB{hint}</span></a>"
            )
    return PAGE.format(user=html.escape(bundle.user), body="\n".join(parts)).encode()


def serve(bundle: Bundle, bind: str, port: int) -> None:
    token = secrets.token_urlsafe(24)
    state = {"fetched_at": None, "dead": False}
    started = time.monotonic()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # noqa: A003 - quiet by default
            sys.stderr.write(f"  [{self.address_string()}] {fmt % args}\n")

        def _expired(self) -> bool:
            if state["dead"]:
                return True
            if time.monotonic() - started > HARD_TIMEOUT:
                state["dead"] = True
            elif state["fetched_at"] and time.monotonic() - state["fetched_at"] > GRACE_AFTER_FETCH:
                state["dead"] = True
            return state["dead"]

        def _send(self, body: bytes, ctype: str, filename: str | None = None) -> None:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            if self._expired():
                self.send_error(404)
                return
            path = self.path.lstrip("/")
            if path == token:
                if state["fetched_at"] is None:
                    state["fetched_at"] = time.monotonic()
                self._send(render_page(bundle, token), "text/html; charset=utf-8")
                return
            prefix = f"{token}/"
            if path.startswith(prefix):
                name = path[len(prefix):]
                if name in bundle.files:
                    _, blob = bundle.files[name]
                    suffix = name[name.rfind("."):] if "." in name else ""
                    self._send(blob, CONTENT_TYPES.get(suffix, "application/octet-stream"), name)
                    return
            # Anything else, including a wrong token, is indistinguishable.
            self.send_error(404)

    server = ThreadingHTTPServer((bind, port), Handler)
    url = f"http://{bind}:{server.server_port}/{token}"

    print(f"\n  {url}\n")
    try:
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except ImportError:
        pass

    print(f"  Bound to {bind} (private address only).")
    print("  Plain HTTP: anyone already on this network could read it inside the")
    print(f"  window. Dies {int(GRACE_AFTER_FETCH)}s after first open, or in "
          f"{int(HARD_TIMEOUT / 60)} minutes. Ctrl-C to kill it now.\n")

    def reaper() -> None:
        while not state["dead"]:
            time.sleep(1)
            if time.monotonic() - started > HARD_TIMEOUT:
                state["dead"] = True
            elif state["fetched_at"] and time.monotonic() - state["fetched_at"] > GRACE_AFTER_FETCH:
                state["dead"] = True
        server.shutdown()

    threading.Thread(target=reaper, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    print("  Link burned." if state["fetched_at"] else "  Stopped; nobody fetched it.")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="one-shot LAN credential handoff")
    parser.add_argument("--bind", help="private address to bind (default: auto-detect)")
    parser.add_argument("--port", type=int, default=0, help="default: an ephemeral port")
    args = parser.parse_args()

    raw = sys.stdin.read().strip()
    if not raw:
        raise SystemExit("nothing on stdin: pipe `vpn user export <name> --json` into this")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit(f"stdin is not the JSON export payload: {e}") from None
    if not payload.get("ok", True):
        raise SystemExit(f"export failed: {payload.get('error', 'unknown error')}")

    bundle = Bundle(payload)
    if bundle.empty():
        raise SystemExit("the export contained no share items")

    serve(bundle, pick_bind(args.bind), args.port)


if __name__ == "__main__":
    main()
