#!/usr/bin/env python3
"""AuthWatch - IDS-style brute-force and credential-stuffing detector (v2).

Pure-stdlib Python monitor that flags brute force, credential stuffing,
password spraying, recon scanning, lockouts, and multi-vector attacks from
SSH/PAM/Dovecot/Postfix/web-server/SIEM logs. Run it on systems you
administer; feeds fail2ban-style actions or a SIEM pipeline.

Usage examples:
  python authwatch.py --logfile /var/log/auth.log
  tail -F /var/log/auth.log | python authwatch.py --format ssh
  python authwatch.py --logfile /var/log/nginx/access.log --format http
  python authwatch.py --logfile events.jsonl --format json --cef
  python authwatch.py --logfile auth.log --allowlist 10.0.0.0/8,192.168.1.1
"""

from __future__ import annotations

import argparse
import configparser
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass

VERSION = "2.0.0"

# ----------------------------------------------------------------------
# Log parsers
# ----------------------------------------------------------------------

SSH_FAIL_RE = re.compile(
    r"sshd\[\d+\]:\s+"
    r"(?:Failed password for (?:invalid user )?(?P<user1>\S+) from (?P<ip1>[\w.:-]+) port \d+|"
    r"Invalid user (?P<user2>\S+) from (?P<ip2>[\w.:-]+))"
)
SSH_ACCEPT_RE = re.compile(
    r"sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\w.:-]+)"
)
SSH_LOCK_RE = re.compile(
    r"sshd\[\d+\]:\s+(?:error: maximum authentication attempts exceeded|"
    r"Connection closed by authenticating user) (?P<user>\S+)"
    r"(?:.*preauth)?(?:.*from (?P<ip>[\w.:-]+))?"
)
PAM_FAIL_RE = re.compile(
    r"pam_unix\(\w+:\w+\):\s+authentication failure.*?"
    r"rhost=(?P<ip>[\w.:-]+).*?user=(?P<user>\S+)"
)
DOVECOT_FAIL_RE = re.compile(
    r"dovecot:.*?(?:Password mismatch|auth failed|Disconnected \(auth failed)"
    r".*?user=<(?P<user>[^>]+)>.*?rip=(?P<ip>[\w.:-]+)"
)
POSTFIX_FAIL_RE = re.compile(
    r"smtpd\[\d+\]:.*?unknown\[(?P<ip>[\w.:-]+)\].*?"
    r"(?:SASL authentication failed|SASL LOGIN authentication failed)"
    r"(?:.*?sasl_username=(?P<user>\S+))?"
)
HTTP_RE = re.compile(
    r'(?P<ip>[\w.:-]+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
)
SYSLOG_TS_RE = re.compile(r"^(?P<mon>\w{3})[ ](?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})")
APACHE_TS_RE = re.compile(r"^(?P<day>\d{2})/(?P<mon>\w{3})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})")

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

LOGIN_PATH_RE = re.compile(
    r"/(login|signin|sign-in|auth|oauth|wp-login\.php|admin|administrator|"
    r"session|account|password|user)(/|$|\?)", re.I)


def parse_epoch(raw: str | None, now: float | None = None) -> float | None:
    """Best-effort timestamp -> epoch. Falls back to None (arrival time)."""
    if not raw:
        return None
    now = now if now is not None else time.time()
    s = raw.strip()
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    m = APACHE_TS_RE.match(s)
    if m and m.group("mon") in MONTHS:
        try:
            d = dt.datetime(int(m.group("year")), MONTHS[m.group("mon")],
                            int(m.group("day")), *map(int, m.group("time").split(":")))
            return d.timestamp()
        except ValueError:
            pass
    m = SYSLOG_TS_RE.match(s)
    if m and m.group("mon") in MONTHS:
        try:
            year = dt.datetime.fromtimestamp(now).year
            d = dt.datetime(year, MONTHS[m.group("mon")], int(m.group("day")),
                            *map(int, m.group("time").split(":")))
            if d.timestamp() > now + 86400:  # rolled into next year
                d = d.replace(year=year - 1)
            return d.timestamp()
        except ValueError:
            pass
    return None


def _num(s: str | None) -> int | None:
    try:
        return int(s) if s is not None else None
    except (TypeError, ValueError):
        return None


def _syslog_ts(line: str) -> str | None:
    m = SYSLOG_TS_RE.match(line)
    return m.group(0) if m else None


def parse_ssh(line: str) -> "Event | None":
    m = SSH_FAIL_RE.search(line)
    if m:
        user = m.group("user1") or m.group("user2")
        ip = m.group("ip1") or m.group("ip2")
        return Event(ts=parse_epoch(_syslog_ts(line)), ip=ip, user=user,
                     kind="auth_failed", service="ssh",
                     detail="ssh failed password/invalid user")
    m = SSH_ACCEPT_RE.search(line)
    if m:
        return Event(ts=parse_epoch(_syslog_ts(line)), ip=m.group("ip"),
                     user=m.group("user"), kind="auth_success", service="ssh",
                     detail="ssh accepted login")
    m = SSH_LOCK_RE.search(line)
    if m:
        return Event(ts=parse_epoch(_syslog_ts(line)),
                     ip=m.group("ip") or "unknown", user=m.group("user"),
                     kind="lockout", service="ssh",
                     detail="ssh max auth attempts exceeded")
    return None


def parse_pam(line: str) -> "Event | None":
    m = PAM_FAIL_RE.search(line)
    if not m:
        return None
    return Event(ts=parse_epoch(_syslog_ts(line)), ip=m.group("ip"),
                 user=m.group("user"), kind="auth_failed", service="pam",
                 detail="pam authentication failure")


def parse_dovecot(line: str) -> "Event | None":
    m = DOVECOT_FAIL_RE.search(line)
    if m:
        return Event(ts=parse_epoch(_syslog_ts(line)), ip=m.group("ip"),
                     user=m.group("user"), kind="auth_failed",
                     service="dovecot", detail="mail auth failure")
    # Lines without a username still carry the source IP.
    m = re.search(r"dovecot:.*?(?:auth failed|Password mismatch).*?"
                  r"rip=(?P<ip>[\w.:-]+)", line)
    if m:
        return Event(ts=parse_epoch(_syslog_ts(line)), ip=m.group("ip"),
                     user=None, kind="auth_failed", service="dovecot",
                     detail="mail auth failure")
    return None


def parse_postfix(line: str) -> "Event | None":
    m = POSTFIX_FAIL_RE.search(line)
    if not m:
        return None
    return Event(ts=parse_epoch(_syslog_ts(line)), ip=m.group("ip"),
                 user=m.group("user"), kind="auth_failed", service="postfix",
                 detail="smtp auth failure")


def parse_http(line: str) -> "Event | None":
    m = HTTP_RE.search(line)
    if not m:
        return None
    path = m.group("path")
    status = _num(m.group("status"))
    is_auth = bool(LOGIN_PATH_RE.search(path))
    kind = None
    if status in (401, 403) and is_auth:
        kind = "auth_failed"
    elif status in (401, 403):
        kind = "denied"
    elif status == 404:
        kind = "recon"
    elif status == 200 and is_auth:
        kind = "auth_success"
    return Event(ts=parse_epoch(m.group("ts")), ip=m.group("ip"), user=None,
                 kind=kind, service="http",
                 detail=f"http {m.group('method')} {path} -> {status}")


def parse_json(line: str) -> "Event | None":
    """SIEM-style JSONL event: ts, src_ip/ip, user, event/kind, service, status."""
    try:
        o = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(o, dict):
        return None
    ts = o.get("ts") or o.get("timestamp") or o.get("time")
    ip = o.get("src_ip") or o.get("ip") or o.get("source_ip")
    if not ip:
        return None
    kind = o.get("kind") or o.get("event") or o.get("event_type")
    status = _num(o.get("status"))
    if kind is None and status in (401, 403):
        kind = "auth_failed"
    service = o.get("service") or "generic"
    return Event(ts=parse_epoch(str(ts) if ts is not None else None),
                 ip=str(ip), user=o.get("user") or o.get("username"),
                 kind=kind, service=service,
                 detail=o.get("detail") or json.dumps(o))




WINDOWS_LOGON_RE = re.compile(
    r'<EventID>(?P<id>\d+)</EventID>.*?'
    r'<Data Name="TargetUserName">(?P<user>[^<]+)</Data>.*?'
    r'<Data Name="IpAddress">(?P<ip>[^<]+)</Data>',
    re.DOTALL)

def parse_windows_event(xml_line: str) -> "Event | None":
    """Parse a wevtutil XML event line (Security4625/4624/4740)."""
    m = WINDOWS_LOGON_RE.search(xml_line)
    if not m:
        return None
    eid = m.group("id")
    ip = m.group("ip") or ""
    user = m.group("user") or ""
    if ip in ("-", "127.0.0.1", "::1", ""):
        return None
    if eid == "4625":
        return Event(ts=time.time(), ip=ip, user=user,
                     kind="auth_failed", service="windows",
                     detail="Windows failed logon (4625)")
    elif eid == "4624":
        return Event(ts=time.time(), ip=ip, user=user,
                     kind="auth_success", service="windows",
                     detail="Windows logon success (4624)")
    elif eid == "4740":
        return Event(ts=time.time(), ip=ip, user=user,
                     kind="lockout", service="windows",
                     detail="Windows account lockout (4740)")
    return None


def query_windows_log(max_events: int = 200) -> list[str]:
    """Query recent Windows Security events via wevtutil."""
    try:
        cmd = ["wevtutil", "qe", "Security",
               "/f:xml", "/c:" + str(max_events), "/rd:true"]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=30, encoding="utf-8",
                                errors="replace")
        if result.returncode != 0:
            return []
        lines = []
        buf = []
        for line in result.stdout.splitlines():
            buf.append(line)
            if "</Event>" in line:
                lines.append(" ".join(buf))
                buf = []
        return lines
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

PARSERS = {"ssh": parse_ssh, "pam": parse_pam, "dovecot": parse_dovecot,
           "postfix": parse_postfix, "http": parse_http, "json": parse_json, "windows": parse_windows_event}
AUTO_ORDER = (parse_ssh, parse_pam, parse_dovecot, parse_postfix,
            parse_http, parse_json, parse_windows_event)


# ----------------------------------------------------------------------
# Event + sliding window
# ----------------------------------------------------------------------

@dataclass
class Event:
    ts: float | None
    ip: str
    user: str | None
    kind: str | None
    service: str = "generic"
    detail: str = ""
    line: int = 0


class SlidingWindow:
    """Keeps recent (timestamped) items per key; prunes on access."""

    def __init__(self, window: float):
        self.window = window
        self._buckets: dict[str, deque] = defaultdict(deque)

    def push(self, key: str, ts: float):
        q = self._buckets[key]
        q.append(ts)
        self._prune(key, q)

    def _prune(self, key: str, q: deque):
        cutoff = self._now() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if not q:
            del self._buckets[key]

    def count(self, key: str) -> int:
        q = self._buckets.get(key)
        if not q:
            return 0
        self._prune(key, q)
        return len(q)

    def set_now(self, now: float):
        self._now = lambda: now

    def _now(self) -> float:
        return time.time()


# ----------------------------------------------------------------------
# Detection rules
# ----------------------------------------------------------------------

@dataclass
class Alert:
    ts: float
    rule: str
    severity: str
    ip: str | None
    user: str | None
    count: int
    window: float
    detail: str


class Detector:
    """Feeds events into sliding windows and raises alerts on thresholds."""

    def __init__(self, window: float = 300.0, fail_threshold: int = 5,
                 stuff_threshold: int = 10, spray_users: int = 5,
                 spray_ips: int = 5, success_after_fails: int = 3,
                 recon_threshold: int = 30, user_threshold: int = 3,
                 persist_buckets: int = 6,
                 allowlist: tuple = (), denylist: tuple = (),
                 focus_users: frozenset = frozenset()):
        self.window = window
        self.fail_threshold = fail_threshold
        self.stuff_threshold = stuff_threshold
        self.spray_users = spray_users
        self.spray_ips = spray_ips
        self.success_after_fails = success_after_fails
        self.recon_threshold = recon_threshold
        self.user_threshold = user_threshold
        self.persist_buckets = persist_buckets
        self.allowlist = tuple(ipaddress.ip_network(c, strict=False)
                               for c in allowlist if c)
        self.denylist = tuple(ipaddress.ip_network(c, strict=False)
                              for c in denylist if c)
        self.focus_users = focus_users
        self.win_fail = SlidingWindow(window)          # ip -> failed ts
        self.win_http = SlidingWindow(window)          # ip -> denied ts
        self.win_recon = SlidingWindow(window)         # ip -> 404 ts
        self.users_failed: dict[str, set] = defaultdict(set)   # ip -> {user}
        self.ips_per_user: dict[str, set] = defaultdict(set)   # user -> {ip}
        self.services_per_ip: dict[str, set] = defaultdict(set)
        self.last_fail: dict[str, float] = {}                 # ip -> last fail ts
        self.seen_buckets: dict[str, set] = defaultdict(set)  # ip -> bucket ids
        self.alerts: list[Alert] = []
        self._alerted: set[tuple] = set()
        self._denylisted: set[str] = set()

    def set_now(self, now: float):
        self.win_fail.set_now(now)
        self.win_http.set_now(now)
        self.win_recon.set_now(now)

    # -- helpers ---------------------------------------------------------

    def _allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allowlist)

    def _denied_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.denylist)

    def _bucket(self, ts: float) -> int:
        return int(ts // self.window)

    def _track_persistence(self, ip: str, ts: float):
        b = self._bucket(ts)
        buckets = self.seen_buckets[ip]
        buckets.add(b)
        # Bound memory: drop buckets older than the persist horizon.
        horizon = self._bucket(ts) - self.persist_buckets * 2
        if len(buckets) > self.persist_buckets * 4:
            buckets = {x for x in buckets if x >= horizon}
            self.seen_buckets[ip] = buckets

    # -- feed ------------------------------------------------------------

    def feed(self, ev: Event):
        if ev.ip == "unknown" or ev.ip is None:
            return
        if self._allowed(ev.ip):
            return
        if self._denied_ip(ev.ip) and ev.ip not in self._denylisted:
            self._denylisted.add(ev.ip)
            self._emit("denylisted_ip", "critical", ev, time.time(), 1,
                       "traffic from denylisted source")
            return
        ts = ev.ts if ev.ts is not None else time.time()
        if ev.kind == "auth_failed":
            self._auth_failed(ev, ts)
        elif ev.kind == "denied":
            self._denied(ev, ts)
        elif ev.kind == "recon":
            self._recon(ev, ts)
        elif ev.kind == "auth_success":
            self._auth_success(ev, ts)
        elif ev.kind == "lockout":
            self._lockout(ev, ts)

    # -- rules -----------------------------------------------------------

    def _auth_failed(self, ev: Event, ts: float):
        self.win_fail.push(ev.ip, ts)
        n = self.win_fail.count(ev.ip)
        self.last_fail[ev.ip] = ts
        self.services_per_ip[ev.ip].add(ev.service)
        self._track_persistence(ev.ip, ts)

        if ev.user:
            self.users_failed[ev.ip].add(ev.user)
            self.ips_per_user[ev.user].add(ev.ip)
            distinct = len(self.users_failed[ev.ip])
            if distinct >= self.spray_users:
                self._emit("username_spray", "medium", ev, ts, distinct,
                           f"single IP tried {distinct} distinct usernames")
            if ev.user in self.focus_users and n >= self.user_threshold:
                self._emit("focused_account_attack", "high", ev, ts, n,
                           f"focused account '{ev.user}' failed {n}x "
                           f"in {self.window:.0f}s")

        if ev.service == "http":
            if n >= self.stuff_threshold:
                self._emit("credential_stuffing", "high", ev, ts, n,
                           f"denied auth requests {n} in {self.window:.0f}s "
                           f"(last: {ev.detail})")
        else:
            if n >= self.fail_threshold:
                self._emit("ssh_bruteforce" if ev.service == "ssh"
                           else "auth_bruteforce", "high", ev, ts, n,
                           f"failed auth count {n} in {self.window:.0f}s")
            if n >= self.fail_threshold * 3:
                self._emit("auth_bruteforce_escalated", "critical", ev, ts, n,
                           f"failed auth count {n} in {self.window:.0f}s "
                           f"(sustained attack)")

        # Slow, persistent attacker spread across many detection windows.
        if len(self.seen_buckets[ev.ip]) >= self.persist_buckets \
                and n >= self.fail_threshold:
            self._emit("persistent_attacker", "high", ev, ts, n,
                       f"spread across {len(self.seen_buckets[ev.ip])} "
                       f"detection windows")

        # Multi-vector: same IP attacking several services.
        services = self.services_per_ip[ev.ip]
        if len(services) >= 2 and n >= self.fail_threshold:
            self._emit("multi_vector_attack", "critical", ev, ts, n,
                       f"attack across services: {', '.join(sorted(services))}")

    def _denied(self, ev: Event, ts: float):
        self.win_http.push(ev.ip, ts)
        self.services_per_ip[ev.ip].add(ev.service)
        n = self.win_http.count(ev.ip)
        if n >= self.stuff_threshold:
            self._emit("credential_stuffing", "high", ev, ts, n,
                       f"denied http requests {n} in {self.window:.0f}s "
                       f"(last: {ev.detail})")

    def _recon(self, ev: Event, ts: float):
        self.win_recon.push(ev.ip, ts)
        self.services_per_ip[ev.ip].add(ev.service)
        n = self.win_recon.count(ev.ip)
        if n >= self.recon_threshold:
            self._emit("scanner_recon", "medium", ev, ts, n,
                       f"{n} 404 responses in {self.window:.0f}s "
                       f"(path enumeration)")

    def _auth_success(self, ev: Event, ts: float):
        if ev.user:
            ips = self.ips_per_user.get(ev.user, set())
            if len(ips) >= self.spray_ips:
                self._emit("password_spray", "high", ev, ts, len(ips),
                           f"username '{ev.user}' seen from "
                           f"{len(ips)} distinct IPs")
        last = self.last_fail.get(ev.ip)
        if last is not None and ts - last <= self.window:
            fails = self.win_fail.count(ev.ip)
            if fails >= self.success_after_fails:
                self._emit("success_after_bruteforce", "critical", ev, ts,
                           fails,
                           f"login succeeded after {fails} failed attempts "
                           f"({ev.detail})")

    def _lockout(self, ev: Event, ts: float):
        self._emit("account_lockout", "critical", ev, ts, 1,
                   f"account lockout / max attempts ({ev.detail})")

    def _emit(self, rule: str, severity: str, ev: Event, ts: float,
              count: int, detail: str):
        # One alert per rule per IP per detection-window bucket avoids floods,
        # while escalation rules get their own buckets/keys.
        key = (rule, ev.ip, ev.user, self._bucket(ts))
        if key in self._alerted:
            return
        self._alerted.add(key)
        self.alerts.append(Alert(ts=ts, rule=rule, severity=severity,
                                 ip=ev.ip, user=ev.user, count=count,
                                 window=self.window, detail=detail))


# ----------------------------------------------------------------------
# Output / actions
# ----------------------------------------------------------------------

def alert_to_dict(a: Alert) -> dict:
    return {
        "ts": dt.datetime.fromtimestamp(a.ts).isoformat(timespec="seconds"),
        "rule": a.rule,
        "severity": a.severity,
        "ip": a.ip,
        "user": a.user,
        "count": a.count,
        "window_s": int(a.window),
        "detail": a.detail,
    }


def alert_to_cef(a: Alert) -> str:
    d = alert_to_dict(a)
    sev = {"low": 2, "medium": 5, "high": 7, "critical": 10}.get(a.severity, 5)
    ext = " ".join(f"{k}={str(v).replace(' ', '%20')}"
                   for k, v in d.items() if v is not None)
    return (f"CEF:0|AuthWatch|authwatch|{VERSION}|{a.rule}|{a.rule}|{sev}|{ext}")


class Bans:
    """Tracks banned IPs; emits (and optionally runs) ban commands once per IP."""

    def __init__(self, cmd_template: str | None = None, dry_run: bool = True,
                 out=sys.stdout):
        self.cmd_template = cmd_template
        self.dry_run = dry_run
        self.out = out
        self.banned: dict[str, float] = {}

    def maybe_ban(self, alert: Alert, ban_window: float = 3600.0):
        if not alert.ip or alert.rule not in (
                "ssh_bruteforce", "auth_bruteforce", "auth_bruteforce_escalated",
                "credential_stuffing", "multi_vector_attack",
                "persistent_attacker", "denylisted_ip"):
            return
        now = time.time()
        last = self.banned.get(alert.ip)
        if last is not None and now - last < ban_window:
            return
        self.banned[alert.ip] = now
        if not self.cmd_template:
            return
        cmd = self.cmd_template.format(ip=alert.ip, user=alert.user or "")
        if self.dry_run:
            print(f"[ban-dry-run] {cmd}", file=self.out)
        else:
            print(f"[ban] {cmd}", file=self.out)
            os.system(cmd)


class Notifiers:
    """Optional syslog (UDP) and webhook (HTTP POST) delivery."""

    def __init__(self, syslog_host: str | None = None,
                 syslog_port: int = 514, webhook_url: str | None = None):
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.webhook_url = webhook_url

    def send(self, alert: Alert, cef: str):
        if self.syslog_host:
            try:
                pri = 133  # local0.notice
                msg = f"<{pri}>authwatch[1]: {cef}"
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(msg.encode("utf-8", "replace"),
                             (self.syslog_host, self.syslog_port))
            except OSError:
                pass
        if self.webhook_url:
            try:
                data = json.dumps([alert_to_dict(alert)]).encode("utf-8")
                req = urllib.request.Request(
                    self.webhook_url, data=data,
                    headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass


# ----------------------------------------------------------------------
# State persistence
# ----------------------------------------------------------------------

class StateStore:
    """Persists per-IP attack counters across restarts (bounded JSON file)."""

    def __init__(self, path: str | None, max_entries: int = 10000):
        self.path = path
        self.max_entries = max_entries
        self.data: dict = {}
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self.data = {}

    def snapshot(self, det: Detector) -> dict:
        out = {}
        for ip, users in det.users_failed.items():
            out[ip] = {
                "users": sorted(users)[:50],
                "services": sorted(det.services_per_ip.get(ip, ()))[:10],
                "buckets": sorted(det.seen_buckets.get(ip, ()))[-200:],
            }
        if len(out) > self.max_entries:
            out = dict(sorted(out.items(), key=lambda kv: -len(kv[1]["users"]))
                       [:self.max_entries])
        return out

    def restore(self, det: Detector):
        if not self.data:
            return
        now = time.time()
        for ip, info in self.data.items():
            if not isinstance(info, dict):
                continue
            users = info.get("users") or []
            buckets = info.get("buckets") or []
            for u in users:
                det.users_failed[ip].add(u)
                det.ips_per_user[u].add(ip)
            det.seen_buckets[ip] = set(buckets)
            det.services_per_ip[ip].update(info.get("services") or [])
            if buckets:
                det.last_fail[ip] = min(now, (max(buckets) + 1) * det.window)

    def save(self, det: Detector):
        if not self.path:
            return
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.snapshot(det), f)
        except OSError:
            pass


# ----------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------

def build_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="authwatch",
        description="IDS-style brute-force / credential-stuffing detector "
                    "(run on systems you administer).")
    ap.add_argument("--config", help="optional .ini config file")
    ap.add_argument("--logfile", help="log file to read (default: stdin)")
    ap.add_argument("--tail", action="store_true",
                    help="follow the log file like tail -F")
    ap.add_argument("--format", choices=["auto", "ssh", "pam", "dovecot",
                                         "postfix", "http", "json"],
                    default="auto", help="log format (default: auto-detect per line)")
    ap.add_argument("--window", type=float, default=300.0,
                    help="detection window in seconds (default: 300)")
    ap.add_argument("--fail-threshold", type=int, default=5,
                    help="failed logins per IP to alert (default: 5)")
    ap.add_argument("--stuff-threshold", type=int, default=10,
                    help="denied HTTP requests per IP to alert (default: 10)")
    ap.add_argument("--spray-users", type=int, default=5,
                    help="distinct usernames per IP to flag (default: 5)")
    ap.add_argument("--spray-ips", type=int, default=5,
                    help="distinct IPs per username to flag (default: 5)")
    ap.add_argument("--success-after", type=int, default=3,
                    help="failures before a successful login is critical (default: 3)")
    ap.add_argument("--recon-threshold", type=int, default=30,
                    help="404 responses per IP to flag scanning (default: 30)")
    ap.add_argument("--user-threshold", type=int, default=3,
                    help="failures on focused accounts to flag (default: 3)")
    ap.add_argument("--persist-buckets", type=int, default=6,
                    help="distinct windows before persistent_attacker (default: 6)")
    ap.add_argument("--allowlist", default="",
                    help="comma-separated IPs/CIDRs to ignore")
    ap.add_argument("--denylist", default="",
                    help="comma-separated IPs/CIDRs to always flag")
    ap.add_argument("--focus-users", default="",
                    help="comma-separated usernames to watch at lower threshold")
    ap.add_argument("--cef", action="store_true",
                    help="emit CEF (SIEM) format alerts")
    ap.add_argument("--json", action="store_true", dest="json_out",
                    help="emit JSON-lines alerts")
    ap.add_argument("--alert-file", help="append JSON-lines alerts to this file")
    ap.add_argument("--syslog-host", help="UDP syslog server (e.g. SIEM collector)")
    ap.add_argument("--syslog-port", type=int, default=514)
    ap.add_argument("--webhook-url",
                    help="POST JSON alerts to this URL (e.g. Slack/Teams bridge)")
    ap.add_argument("--state-file",
                    help="persist/restore per-IP state across runs")
    ap.add_argument("--max-state", type=int, default=10000,
                    help="max IPs kept in state file (default: 10000)")
    ap.add_argument("--ban-cmd", metavar="TEMPLATE",
                    help="ban command template, e.g. "
                         "'iptables -A INPUT -s {ip} -j DROP'")
    ap.add_argument("--ban", action="store_true",
                    help="actually execute ban commands (default: dry-run)")
    ap.add_argument("--ban-window", type=float, default=3600.0,
                    help="don't re-ban an IP within this many seconds (default: 3600)")
    ap.add_argument("--windows-log", action="store_true",
                    help="query Windows Security event log via wevtutil")
    ap.add_argument("--win-max-events", type=int, default=200,
                    help="max events per wevtutil query (default: 200)")
    ap.add_argument("--create-task", metavar="NAME",
                    help="create a Windows scheduled task and exit")
    ap.add_argument("--task-interval", type=int, default=10,
                    help="task interval in minutes (default: 10)")
    ap.add_argument("--version", action="version", version=f"authwatch {VERSION}")
    return ap.parse_args(argv)


def _split_csv(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def load_config(path: str | None) -> dict:
    """Read [detect]/[output] .ini sections into a flat dict."""
    cfg: dict = {}
    if not path or not os.path.isfile(path):
        return cfg
    p = configparser.ConfigParser()
    p.read(path)
    for section in ("detect", "output"):
        if p.has_section(section):
            for k, v in p.items(section):
                cfg[k] = v
    return cfg


def apply_config(args, cfg: dict):
    """Overlay config-file values onto argparse defaults (CLI flags win)."""
    defaults = vars(build_args([]))
    current = vars(args)
    for k, v in cfg.items():
        if k not in current or k not in defaults:
            continue
        if current[k] != defaults[k]:
            continue  # explicitly set on the command line
        cur = defaults[k]
        if isinstance(cur, bool):
            setattr(args, k, str(v).lower() in ("1", "true", "yes", "on"))
        elif isinstance(cur, int):
            try:
                setattr(args, k, int(v))
            except ValueError:
                pass
        elif isinstance(cur, float):
            try:
                setattr(args, k, float(v))
            except ValueError:
                pass
        else:
            setattr(args, k, v)


def build_detector(args) -> Detector:
    return Detector(window=args.window,
                    fail_threshold=args.fail_threshold,
                    stuff_threshold=args.stuff_threshold,
                    spray_users=args.spray_users,
                    spray_ips=args.spray_ips,
                    success_after_fails=args.success_after,
                    recon_threshold=args.recon_threshold,
                    user_threshold=args.user_threshold,
                    persist_buckets=args.persist_buckets,
                    allowlist=tuple(_split_csv(args.allowlist)),
                    denylist=tuple(_split_csv(args.denylist)),
                    focus_users=frozenset(_split_csv(args.focus_users)))


def parse_line(line: str, fmt: str) -> Event | None:
    if fmt == "auto":
        for fn in AUTO_ORDER:
            ev = fn(line)
            if ev is not None:
                return ev
        return None
    return PARSERS[fmt](line)


def flush_alerts(det: Detector, args: argparse.Namespace | None = None,
                 out=sys.stdout, bans: Bans | None = None,
                 notifiers: Notifiers | None = None):
    for a in det.alerts:
        if args is None or args.json_out:
            print(json.dumps(alert_to_dict(a)), file=out)
        elif args.cef:
            cef = alert_to_cef(a)
            print(cef, file=out)
            if notifiers is not None:
                notifiers.send(a, cef)
        else:
            print(f"[{dt.datetime.fromtimestamp(a.ts).isoformat(timespec='seconds')}] "
                  f"{a.severity.upper():8s} {a.rule:28s} ip={a.ip or '-':<15s} "
                  f"user={a.user or '-':<12s} count={a.count} {a.detail}", file=out)
            if notifiers is not None:
                notifiers.send(a, alert_to_cef(a))
        if args is not None and args.alert_file:
            with open(args.alert_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_to_dict(a)) + "\n")
        if bans is not None:
            bans.maybe_ban(a, args.ban_window if args else 3600.0)
    det.alerts.clear()



def _create_scheduled_task(args):
    """Create a Windows Scheduled Task via schtasks."""
    import sys as _sys
    name = args.create_task
    interval = args.task_interval
    log_path = os.path.abspath(args.logfile) if args.logfile else ""
    script = os.path.abspath(__file__)
    # Build command: python authwatch.py --logfile LOG --tail --cef --alert-file FILE
    alert_file = os.path.abspath(f"{name}-alerts.jsonl")
    cmd_parts = [sys.executable, repr(script)]
    if log_path:
        cmd_parts += ["--logfile", repr(log_path)]
    cmd_parts += ["--tail", "--json", "--alert-file", repr(alert_file)]
    cmd = " ".join(cmd_parts)
    schtasks_cmd = [
        "schtasks", "/create", "/tn", name, "/tr", cmd,
        "/sc", "minute", "/mo", str(interval), "/f"
    ]
    print(f"[task] Creating scheduled task '{name}' (every {interval} min)")
    print(f"[task] Command: {cmd}")
    print(f"[task] Alerts -> {alert_file}")
    result = subprocess.run(schtasks_cmd, capture_output=True, text=True,
                            timeout=30)
    if result.returncode == 0:
        print(f"[task] OK: {result.stdout.strip()}")
    else:
        print(f"[task] FAILED: {result.stderr.strip()}", file=sys.stderr)

def main(argv=None) -> int:
    args = build_args(argv)
    apply_config(args, load_config(args.config))
    if args.create_task:
        _create_scheduled_task(args)
        return 0
    if args.logfile and os.path.isfile(args.logfile):
        src = open(args.logfile, "r", encoding="utf-8", errors="replace")
    else:
        src = sys.stdin
    det = build_detector(args)
    state = StateStore(args.state_file, args.max_state)
    state.restore(det)
    bans = Bans(cmd_template=args.ban_cmd, dry_run=not args.ban)
    notifiers = Notifiers(syslog_host=args.syslog_host,
                          syslog_port=args.syslog_port,
                          webhook_url=args.webhook_url)
    if args.windows_log:
        try:
            while True:
                for xml in query_windows_log(args.win_max_events):
                    ev = parse_windows_event(xml)
                    if ev is not None:
                        det.feed(ev)
                flush_alerts(det, args, bans=bans, notifiers=notifiers)
                time.sleep(10)
        except KeyboardInterrupt:
            return 0
    elif args.tail:
        try:
            while True:
                line = src.readline()
                if line:
                    line = line.strip()
                    if line:
                        ev = parse_line(line, args.format)
                        if ev is not None:
                            det.feed(ev)
                            flush_alerts(det, args, bans=bans,
                                         notifiers=notifiers)
                else:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            return 0
    else:
        for lineno, line in enumerate(src, 1):
            line = line.strip()
            if not line:
                continue
            ev = parse_line(line, args.format)
            if ev is not None:
                ev.line = lineno
                det.feed(ev)
        flush_alerts(det, args, bans=bans, notifiers=notifiers)
    state.save(det)
    return 0


if __name__ == "__main__":
    sys.exit(main())
