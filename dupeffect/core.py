"""Core analysis for dupeffect.

A trace is a list of tool-call events. Each event is a dict with at least
``tool``; optional fields are ``id``, ``ts`` (seconds or ISO-8601), ``args``
(dict), ``status`` (ok | error | timeout | unknown | 5xx code), ``agent`` and
``idempotency_key``. The key may also live inside ``args`` under common names.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Iterable

SEVERITIES = ["info", "low", "medium", "high"]

DEFAULT_EFFECT = (r"(send|post|create|charge|pay|transfer|deploy|delete|remove|write|"
                  r"update|insert|publish|book|order|refund|merge|push|email|invite|"
                  r"submit|cancel|provision|schedule|upload|commit|execute|run_shell)")
DEFAULT_READ = r"(^|[.:/])(get|list|search|read|fetch|status|query|lookup|find|describe|check|verify|head)(_|-|$|[A-Z])"
KEY_NAMES = ("idempotency_key", "idempotencyKey", "Idempotency-Key", "idempotency-key",
             "client_token", "clientToken", "client_request_id", "request_id", "dedupe_key")
DEFAULT_VOLATILE = ("ts", "timestamp", "time", "now", "nonce", "trace_id", "span_id",
                    "attempt", "retry", "request_time", "sent_at")
AMBIGUOUS = {"timeout", "unknown", "lost", "cancelled_client", "connection_reset"}


@dataclass
class Config:
    effect_re: str = DEFAULT_EFFECT
    read_re: str = DEFAULT_READ
    volatile: tuple = DEFAULT_VOLATILE
    window: float = 3600.0          # seconds; duplicates further apart are ignored
    require_key: tuple = ()         # tool regexes that must carry an idempotency key
    idempotent_tools: tuple = ()    # tool regexes that are safe to repeat (PUT-like)

    def is_effect(self, tool: str) -> bool:
        if any(re.search(p, tool, re.I) for p in self.idempotent_tools):
            return False
        if re.search(self.read_re, tool):
            return False
        return re.search(self.effect_re, tool, re.I) is not None

    def is_read(self, tool: str) -> bool:
        return re.search(self.read_re, tool) is not None


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    events: list
    tool: str
    agent: str | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


RULES = {
    "DUP001": "double-fire: identical side effect repeated after it already succeeded",
    "DUP002": "blind retry: side effect retried after an ambiguous outcome with no key and no verification read",
    "DUP003": "key rotation: retry after an ambiguous outcome used a new idempotency key, defeating dedupe",
    "DUP004": "key reuse conflict: same idempotency key sent with different arguments",
    "DUP005": "missing key: tool requires an idempotency key but the call has none",
    "DUP006": "verified retry: ambiguous outcome was checked with a read before retrying (informational)",
}


def _ts(v: Any, idx: int) -> float:
    if v is None:
        return float(idx)
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return float(idx)


def _status(v: Any) -> str:
    if v is None:
        return "ok"
    if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
        code = int(v)
        if code in (408, 504):
            return "timeout"
        if code >= 500:
            return "unknown"
        return "ok" if code < 400 else "error"
    s = str(v).lower()
    if s in ("ok", "success", "succeeded", "done", "completed"):
        return "ok"
    if s in AMBIGUOUS or "timeout" in s or "timed out" in s:
        return "timeout" if "time" in s else "unknown"
    return "error"


def _strip(obj: Any, volatile: set) -> Any:
    if isinstance(obj, dict):
        return {k: _strip(v, volatile) for k, v in sorted(obj.items())
                if k not in volatile and k not in KEY_NAMES}
    if isinstance(obj, list):
        return [_strip(x, volatile) for x in obj]
    if isinstance(obj, str):
        return " ".join(obj.split())
    return obj


def _key(ev: dict) -> str | None:
    if ev.get("idempotency_key"):
        return str(ev["idempotency_key"])
    args = ev.get("args") or {}
    if isinstance(args, dict):
        for k in KEY_NAMES:
            if args.get(k):
                return str(args[k])
        hdrs = args.get("headers")
        if isinstance(hdrs, dict):
            for k, v in hdrs.items():
                if k.lower() in ("idempotency-key", "x-idempotency-key") and v:
                    return str(v)
    return None


@dataclass
class Call:
    idx: int
    id: str
    tool: str
    agent: str | None
    ts: float
    status: str
    key: str | None
    sig: str
    raw: dict


def normalize(events: Iterable[dict], cfg: Config) -> list[Call]:
    vol = set(cfg.volatile)
    out = []
    for i, ev in enumerate(events):
        if not isinstance(ev, dict) or "tool" not in ev:
            continue
        args = ev.get("args") or {}
        sig = json.dumps(_strip(args, vol), sort_keys=True, default=str)
        out.append(Call(i, str(ev.get("id", f"#{i}")), str(ev["tool"]), ev.get("agent"),
                        _ts(ev.get("ts"), i), _status(ev.get("status")), _key(ev), sig, ev))
    return out


def analyze(events: Iterable[dict], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    calls = normalize(events, cfg)
    findings: list[Finding] = []
    effects = [c for c in calls if cfg.is_effect(c.tool)]

    # DUP005 missing key
    for c in effects:
        if c.key is None and any(re.search(p, c.tool, re.I) for p in cfg.require_key):
            findings.append(Finding("DUP005", "low", f"{c.tool} call {c.id} has no idempotency key",
                                    [c.id], c.tool, c.agent))

    # DUP004 key reuse with different args
    by_key: dict = {}
    for c in effects:
        if c.key is None:
            continue
        prev = by_key.get((c.tool, c.key))
        if prev and prev.sig != c.sig:
            findings.append(Finding("DUP004", "medium",
                f"{c.tool} reused idempotency key '{c.key}' with different arguments ({prev.id} then {c.id})",
                [prev.id, c.id], c.tool, c.agent, {"key": c.key}))
        by_key.setdefault((c.tool, c.key), c)

    # pairwise duplicate analysis on identical (tool, sig)
    seen_pairs = set()
    for j, c in enumerate(effects):
        for p in reversed(effects[:j]):
            if p.tool != c.tool or p.sig != c.sig:
                continue
            if c.ts - p.ts > cfg.window:
                break
            pair = (p.id, c.id)
            if pair in seen_pairs:
                break
            seen_pairs.add(pair)
            same_key = p.key is not None and p.key == c.key
            if same_key:
                break  # dedupe works as designed
            between = [x for x in calls if p.idx < x.idx < c.idx]
            verified = any(cfg.is_read(x.tool) and not cfg.is_effect(x.tool) for x in between)
            if p.status == "ok":
                sev = "high" if c.key is None or p.key is None else "medium"
                findings.append(Finding("DUP001", sev,
                    f"{c.tool} fired again with identical arguments after {p.id} already succeeded ({c.id})",
                    [p.id, c.id], c.tool, c.agent,
                    {"gap_s": round(c.ts - p.ts, 3), "cross_agent": p.agent != c.agent}))
            elif p.status in ("timeout", "unknown"):
                if p.key is not None and c.key is not None and p.key != c.key:
                    findings.append(Finding("DUP003", "high",
                        f"{c.tool} retry {c.id} after {p.status} on {p.id} rotated the idempotency key "
                        f"('{p.key}' to '{c.key}'), so the server cannot dedupe it",
                        [p.id, c.id], c.tool, c.agent))
                elif verified:
                    findings.append(Finding("DUP006", "info",
                        f"{c.tool} retry {c.id} after {p.status} on {p.id} was preceded by a verification read",
                        [p.id, c.id], c.tool, c.agent,
                        {"reads": [x.id for x in between if cfg.is_read(x.tool)]}))
                else:
                    findings.append(Finding("DUP002", "high",
                        f"{c.tool} retried as {c.id} after {p.status} on {p.id} with no idempotency key "
                        f"and no read to check whether the first attempt landed",
                        [p.id, c.id], c.tool, c.agent, {"cross_agent": p.agent != c.agent}))
            # definite errors are safe to retry
            break
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (-order[f.severity], f.rule))
    return findings


def load_trace(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    if text[0] in "[{":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                data = data.get("events") or data.get("calls") or data.get("trace") or [data]
            return list(data)
        except json.JSONDecodeError:
            pass
    return [json.loads(line) for line in text.splitlines() if line.strip()]
