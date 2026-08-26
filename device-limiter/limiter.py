"""Best-effort "1 connected device per user" enforcer for sing-box.

sing-box has no native per-user device cap (SagerNet/sing-box#2579, closed
"not planned"), and its Clash-compatible API's /connections endpoint does
NOT include which user a connection belongs to (verified against a live
1.13.19 instance: metadata only has sourceIP/sourcePort/host/type, no user
field) -- despite the Clash API being the obvious place to look for it.

The only place a connection's (user, source IP) pairing shows up at all is
sing-box's own log output, e.g.:

    ... inbound/vless[vless-in]: inbound connection from 192.168.1.1:62236
    ... inbound/vless[vless-in]: [asel1x] inbound connection to ya.ru:443

both lines share the same bracketed connection-tracking ID. So this daemon:
1. Tails sing-box's log file (config/00_base.json sets `log.output` to write
   there instead of the console) to build a (sourceIP, sourcePort) -> user
   map.
2. Polls the Clash API for the actual list of live connections + their IDs
   (needed to actually close one).
3. Joins the two on sourceIP:sourcePort to know which user each live
   connection belongs to, and kicks extra devices.

This is a heuristic, IP-based approximation, not hard admission control:
- Multiple real devices sharing one NAT/CGNAT IP are NOT detected (false negative).
- A user's IP changing quickly (mobile handoff) can momentarily look like two
  devices; the hysteresis window exists to avoid punishing that.
- Nothing stops a user from further-proxying behind one already-admitted device.
- A connection is only actionable once its log line has been seen -- there's
  a small window right after connect where it's still "unattributed" and left
  alone.

`log.output` has no built-in rotation, so this daemon also self-truncates the
log file once it exceeds LOG_MAX_BYTES -- sing-box writes in append mode, so
truncating externally is safe (same trick logrotate's `copytruncate` uses).
This means `docker compose logs sing-box` no longer shows anything; use
`tail -f data/sing-box.log` on the host instead.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

CLASH_API_URL = os.environ.get("CLASH_API_URL", "http://127.0.0.1:9090").rstrip("/")
CLASH_API_SECRET = os.environ.get("CLASH_API_SECRET", "")
POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "5"))
HYSTERESIS_POLLS = int(os.environ.get("HYSTERESIS_POLLS", "2"))
LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "/var/lib/sing-box/sing-box.log")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
MAPPING_TTL_SECONDS = 600

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LOG_LINE_RE = re.compile(r"\[(\d+)\s+\S+\]\s+inbound/\S+:\s+(.*)$")
FROM_RE = re.compile(r"^inbound connection from ([0-9a-fA-F.:]+):(\d+)$")
USER_RE = re.compile(r"^\[([^\]]+)\] inbound connection to ")

_log_pos = 0
_pending_conn_ids: dict[str, tuple[str, str, float]] = {}  # conn_id -> (ip, port, seen_at)
_addr_to_user: dict[str, tuple[str, float]] = {}  # "ip:port" -> (user, seen_at)
_first_payload_logged = False
# (user, ip) -> number of consecutive polls seen as "extra"
_overlap_streak: dict[tuple[str, str], int] = {}


def _request(method: str, path: str, timeout: float = 5.0):
    req = urllib.request.Request(f"{CLASH_API_URL}{path}", method=method)
    if CLASH_API_SECRET:
        req.add_header("Authorization", f"Bearer {CLASH_API_SECRET}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return json.loads(body) if body else None


def _prune_stale(mapping: dict, now: float) -> None:
    stale = [k for k, v in mapping.items() if now - v[-1] > MAPPING_TTL_SECONDS]
    for k in stale:
        mapping.pop(k, None)


def _read_new_log_lines() -> list[str]:
    global _log_pos

    if not os.path.exists(LOG_FILE_PATH):
        return []

    size = os.path.getsize(LOG_FILE_PATH)
    if size < _log_pos:
        _log_pos = 0  # file was truncated (by us, or by sing-box restarting)

    with open(LOG_FILE_PATH, "rb") as f:
        f.seek(_log_pos)
        data = f.read()

    last_newline = data.rfind(b"\n")
    if last_newline == -1:
        return []  # no complete line yet

    complete = data[: last_newline + 1]
    _log_pos += len(complete)
    return complete.decode("utf-8", errors="replace").splitlines()


def _maybe_rotate_log() -> None:
    if not os.path.exists(LOG_FILE_PATH):
        return
    if os.path.getsize(LOG_FILE_PATH) < LOG_MAX_BYTES:
        return
    global _log_pos
    with open(LOG_FILE_PATH, "r+b") as f:
        f.truncate(0)
    _log_pos = 0
    print(f"[device-limiter] rotated {LOG_FILE_PATH} (exceeded {LOG_MAX_BYTES} bytes)", flush=True)


def update_user_mapping() -> None:
    now = time.time()
    for raw_line in _read_new_log_lines():
        line = ANSI_RE.sub("", raw_line)
        m = LOG_LINE_RE.search(line)
        if not m:
            continue
        conn_id, rest = m.groups()

        fm = FROM_RE.match(rest)
        if fm:
            ip, port = fm.groups()
            _pending_conn_ids[conn_id] = (ip, port, now)
            continue

        um = USER_RE.match(rest)
        if um:
            user = um.group(1)
            addr = _pending_conn_ids.get(conn_id)
            if addr:
                ip, port, _ = addr
                _addr_to_user[f"{ip}:{port}"] = (user, now)

    _prune_stale(_pending_conn_ids, now)
    _prune_stale(_addr_to_user, now)


def poll_once() -> None:
    global _first_payload_logged

    update_user_mapping()

    try:
        payload = _request("GET", "/connections")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[device-limiter] could not reach Clash API: {e}", file=sys.stderr, flush=True)
        return

    connections = (payload or {}).get("connections", [])

    if not _first_payload_logged:
        print(
            f"[device-limiter] first /connections payload (for sanity check): "
            f"{json.dumps(payload)[:2000]}",
            flush=True,
        )
        _first_payload_logged = True

    # user -> ip -> list of connection ids
    by_user: dict[str, dict[str, list[str]]] = {}
    # user -> ip -> most recent "start" timestamp seen
    latest_start: dict[str, dict[str, str]] = {}

    for conn in connections:
        metadata = conn.get("metadata", {})
        ip = metadata.get("sourceIP")
        port = metadata.get("sourcePort")
        conn_id = conn.get("id")
        if not ip or not port or not conn_id:
            continue
        entry = _addr_to_user.get(f"{ip}:{port}")
        if not entry:
            continue  # not attributed to a user yet -- leave alone this poll
        user, _ = entry
        by_user.setdefault(user, {}).setdefault(ip, []).append(conn_id)
        start = conn.get("start", "")
        if start > latest_start.setdefault(user, {}).get(ip, ""):
            latest_start[user][ip] = start

    seen_this_poll = set()

    for user, ips in by_user.items():
        if len(ips) <= 1:
            continue
        # Keep whichever IP has the most recently started connection; the rest are "extra".
        current_ip = max(ips, key=lambda ip: latest_start[user][ip])
        for ip, conn_ids in ips.items():
            if ip == current_ip:
                continue
            key = (user, ip)
            seen_this_poll.add(key)
            _overlap_streak[key] = _overlap_streak.get(key, 0) + 1
            if _overlap_streak[key] < HYSTERESIS_POLLS:
                continue
            for conn_id in conn_ids:
                try:
                    _request("DELETE", f"/connections/{conn_id}")
                    print(
                        f"[device-limiter] kicked user={user!r} ip={ip} "
                        f"(kept ip={current_ip}) conn={conn_id}",
                        flush=True,
                    )
                except (urllib.error.URLError, TimeoutError) as e:
                    print(f"[device-limiter] failed to close connection {conn_id}: {e}",
                          file=sys.stderr, flush=True)
            _overlap_streak.pop(key, None)

    # Drop streak counters for (user, ip) pairs that no longer overlap.
    for key in list(_overlap_streak):
        if key not in seen_this_poll:
            _overlap_streak.pop(key, None)

    _maybe_rotate_log()


def main() -> None:
    print(
        f"[device-limiter] starting: url={CLASH_API_URL} interval={POLL_INTERVAL_SECONDS}s "
        f"hysteresis={HYSTERESIS_POLLS} polls log={LOG_FILE_PATH} max_bytes={LOG_MAX_BYTES}",
        flush=True,
    )
    while True:
        poll_once()
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
