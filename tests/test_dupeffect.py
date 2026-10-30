import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dupeffect.core import Config, analyze, load_trace, _status  # noqa: E402
from dupeffect.cli import main  # noqa: E402


def rules(events, **kw):
    return sorted(f.rule for f in analyze(events, Config(**kw)))


class TestRules(unittest.TestCase):
    def test_double_fire_after_success(self):
        ev = [{"id": "a", "tool": "send_email", "args": {"to": "x"}, "status": "ok"},
              {"id": "b", "tool": "send_email", "args": {"to": "x"}, "status": "ok"}]
        self.assertEqual(rules(ev), ["DUP001"])

    def test_volatile_and_whitespace_ignored(self):
        ev = [{"tool": "send_email", "args": {"body": "hi  there", "ts": 1}},
              {"tool": "send_email", "args": {"body": "hi there", "ts": 2}}]
        self.assertEqual(rules(ev), ["DUP001"])

    def test_different_args_not_duplicate(self):
        ev = [{"tool": "send_email", "args": {"to": "x"}}, {"tool": "send_email", "args": {"to": "y"}}]
        self.assertEqual(rules(ev), [])

    def test_blind_retry_after_timeout(self):
        ev = [{"tool": "create_refund", "args": {"c": 1}, "status": "timeout"},
              {"tool": "create_refund", "args": {"c": 1}, "status": "ok"}]
        self.assertEqual(rules(ev), ["DUP002"])

    def test_verified_retry_is_info(self):
        ev = [{"tool": "create_refund", "args": {"c": 1}, "status": "timeout"},
              {"tool": "list_refunds", "args": {}},
              {"tool": "create_refund", "args": {"c": 1}, "status": "ok"}]
        f = analyze(ev)
        self.assertEqual([(x.rule, x.severity) for x in f], [("DUP006", "info")])

    def test_definite_error_retry_is_fine(self):
        ev = [{"tool": "create_refund", "args": {"c": 1}, "status": 400},
              {"tool": "create_refund", "args": {"c": 1}, "status": "ok"}]
        self.assertEqual(rules(ev), [])

    def test_same_key_retry_is_fine(self):
        ev = [{"tool": "charge", "args": {"a": 1, "idempotency_key": "k"}, "status": "timeout"},
              {"tool": "charge", "args": {"a": 1, "idempotency_key": "k"}, "status": "ok"}]
        self.assertEqual(rules(ev), [])

    def test_key_rotation(self):
        ev = [{"tool": "charge", "args": {"a": 1}, "idempotency_key": "k1", "status": "504"},
              {"tool": "charge", "args": {"a": 1}, "idempotency_key": "k2", "status": "ok"}]
        self.assertEqual(rules(ev), ["DUP003"])

    def test_key_in_headers(self):
        ev = [{"tool": "http_post", "args": {"u": "/pay", "headers": {"Idempotency-Key": "z"}}, "status": "timeout"},
              {"tool": "http_post", "args": {"u": "/pay", "headers": {"Idempotency-Key": "z"}}, "status": "ok"}]
        # headers dict differs only by key, which is identical, so no finding
        self.assertEqual(rules(ev), [])

    def test_key_reuse_conflict(self):
        ev = [{"tool": "charge", "args": {"a": 1, "idempotency_key": "k"}},
              {"tool": "charge", "args": {"a": 2, "idempotency_key": "k"}}]
        self.assertEqual(rules(ev), ["DUP004"])

    def test_missing_key(self):
        ev = [{"tool": "payments.charge", "args": {"a": 1}}]
        self.assertEqual(rules(ev, require_key=(r"payments\.",)), ["DUP005"])

    def test_reads_are_not_effects(self):
        ev = [{"tool": "get_status", "args": {}}, {"tool": "get_status", "args": {}}]
        self.assertEqual(rules(ev), [])

    def test_update_status_is_effect(self):
        self.assertTrue(Config().is_effect("update_status"))
        self.assertFalse(Config().is_effect("stripe.get_charge"))

    def test_idempotent_override(self):
        ev = [{"tool": "update_record", "args": {"a": 1}}, {"tool": "update_record", "args": {"a": 1}}]
        self.assertEqual(rules(ev, idempotent_tools=("update_record",)), [])

    def test_window(self):
        ev = [{"tool": "send_email", "args": {"to": "x"}, "ts": 0},
              {"tool": "send_email", "args": {"to": "x"}, "ts": 7200}]
        self.assertEqual(rules(ev, window=3600), [])

    def test_iso_timestamps(self):
        ev = [{"tool": "send_email", "args": {"to": "x"}, "ts": "2026-10-30T10:00:00Z"},
              {"tool": "send_email", "args": {"to": "x"}, "ts": "2026-10-30T10:00:05Z"}]
        f = analyze(ev)
        self.assertEqual(f[0].extra["gap_s"], 5.0)

    def test_status_parsing(self):
        self.assertEqual(_status(None), "ok")
        self.assertEqual(_status(504), "timeout")
        self.assertEqual(_status("502"), "unknown")
        self.assertEqual(_status(409), "error")
        self.assertEqual(_status("Request timed out"), "timeout")


class TestIO(unittest.TestCase):
    def test_load_json_and_jsonl(self):
        self.assertEqual(len(load_trace('[{"tool":"a"},{"tool":"b"}]')), 2)
        self.assertEqual(len(load_trace('{"events":[{"tool":"a"}]}')), 1)
        self.assertEqual(len(load_trace('{"tool":"a"}\n{"tool":"b"}\n')), 2)

    def test_example_and_fail_on(self):
        ex = os.path.join(ROOT, "examples", "refund_agent.jsonl")
        out = subprocess.run([sys.executable, "-m", "dupeffect", ex, "--format", "json",
                              "--fail-on", "high"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(out.returncode, 1)
        data = json.loads(out.stdout)
        got = sorted(f["rule"] for f in data[ex])
        self.assertEqual(got, ["DUP001", "DUP002", "DUP003", "DUP004", "DUP006"])

    def test_rules_flag(self):
        self.assertEqual(main(["--rules"]), 0)


if __name__ == "__main__":
    unittest.main()
