from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import Config, analyze, load_trace, RULES, SEVERITIES


def render_text(path, fs):
    lines = [f"{path}: {len(fs)} finding(s)"]
    for f in fs:
        lines.append(f"  [{f.severity.upper():6}] {f.rule} {f.message}")
    return "\n".join(lines)


def render_md(path, fs):
    out = [f"### {path}", "", "| Severity | Rule | Tool | Events | Detail |", "|---|---|---|---|---|"]
    for f in fs:
        out.append(f"| {f.severity} | {f.rule} | `{f.tool}` | {', '.join(f.events)} | {f.message} |")
    if not fs:
        out.append("| - | - | - | - | no duplicated side effects |")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="dupeffect",
        description="Find duplicated side effects (double charges, double emails) in agent tool-call traces.")
    ap.add_argument("traces", nargs="*", help="JSON or JSONL trace files ('-' for stdin)")
    ap.add_argument("--format", choices=["text", "json", "md"], default="text")
    ap.add_argument("--window", type=float, default=3600.0, help="max seconds between duplicates (default 3600)")
    ap.add_argument("--effect", help="regex for side-effecting tool names (overrides default)")
    ap.add_argument("--read", help="regex for verification/read tool names (overrides default)")
    ap.add_argument("--volatile", action="append", default=[], help="extra arg key to ignore when comparing")
    ap.add_argument("--require-key", action="append", default=[], help="tool regex that must carry an idempotency key")
    ap.add_argument("--idempotent", action="append", default=[], help="tool regex that is safe to repeat")
    ap.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at or above this severity")
    ap.add_argument("--rules", action="store_true", help="list rules and exit")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    if a.rules:
        for k, v in RULES.items():
            print(f"{k}  {v}")
        return 0
    if not a.traces:
        ap.error("give at least one trace file")
    cfg = Config(window=a.window, require_key=tuple(a.require_key), idempotent_tools=tuple(a.idempotent))
    if a.effect:
        cfg.effect_re = a.effect
    if a.read:
        cfg.read_re = a.read
    cfg.volatile = tuple(cfg.volatile) + tuple(a.volatile)
    results = {}
    for p in a.traces:
        text = sys.stdin.read() if p == "-" else open(p, encoding="utf-8").read()
        results[p] = analyze(load_trace(text), cfg)
    if a.format == "json":
        print(json.dumps({p: [f.to_dict() for f in fs] for p, fs in results.items()}, indent=2))
    else:
        r = render_md if a.format == "md" else render_text
        print("\n\n".join(r(p, fs) for p, fs in results.items()))
    if a.fail_on:
        th = SEVERITIES.index(a.fail_on)
        if any(SEVERITIES.index(f.severity) >= th for fs in results.values() for f in fs):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
