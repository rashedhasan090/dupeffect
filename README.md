# dupeffect

Find duplicated side effects in AI agent tool-call traces: the refund that went out twice, the email a second agent re-sent, the charge retried with a fresh idempotency key.

Agents retry. A tool call times out, the model sees an error, and it calls the tool again. If the first attempt actually landed, the customer now has two refunds. `dupeffect` reads a trace of tool calls offline and reports where that happened or could have happened.

## What is novel

Loop detectors look for repetition in general. Approval checkers look at whether a call was allowed. `dupeffect` looks at one specific failure, **at-least-once execution of non-idempotent side effects**, and reasons about it the way a payments engineer would:

- It separates **definite failures** (4xx, explicit errors, safe to retry) from **ambiguous outcomes** (timeouts, 5xx, lost connections), where the first call may or may not have executed.
- It tracks **idempotency keys** wherever they live (a top-level field, inside `args`, or an `Idempotency-Key` header) and catches the subtle bug where a retry generates a **new** key, which silently defeats server-side dedupe.
- It credits a **verification read** (`get_*`, `list_*`, `check_*`, ...) between an ambiguous call and its retry, downgrading the retry to informational.
- It compares arguments after dropping **volatile fields** (timestamps, nonces, trace ids) and collapsing whitespace, so a re-sent email with a new `sent_at` still counts as the same email.
- It works **across agents**, so a duplicate fired by a follow-up sub-agent is caught and labeled `cross_agent`.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| DUP001 | high | Identical side effect repeated after the first already succeeded |
| DUP002 | high | Retry after an ambiguous outcome with no idempotency key and no verification read |
| DUP003 | high | Retry after an ambiguous outcome used a different idempotency key |
| DUP004 | medium | Same idempotency key reused with different arguments |
| DUP005 | low | Tool listed with `--require-key` called without a key |
| DUP006 | info | Ambiguous outcome checked with a read before retrying |

## Install

```bash
pip install git+https://github.com/rashedhasan090/dupeffect
# or, from a clone, no install needed:
python3 -m dupeffect --help
```

Pure Python standard library, Python 3.9+, no network access.

## Trace format

JSON array, `{"events": [...]}`, or JSONL. Each event needs `tool`; everything else is optional.

```json
{"id": "c1", "ts": 0, "agent": "support", "tool": "stripe.create_refund",
 "args": {"charge": "ch_9", "amount": 4200}, "status": "timeout", "idempotency_key": null}
```

`ts` may be seconds or ISO-8601. `status` may be `ok`, `error`, `timeout`, `unknown`, or an HTTP code (408/504 are timeouts, other 5xx are unknown, 4xx are definite errors). A missing status means `ok`.

## Demo

```bash
python3 -m dupeffect examples/refund_agent.jsonl
```

```
examples/refund_agent.jsonl: 5 finding(s)
  [HIGH  ] DUP001 gmail.send_email fired again with identical arguments after c3 already succeeded (c4)
  [HIGH  ] DUP002 stripe.create_refund retried as c2 after timeout on c1 with no idempotency key and no read to check whether the first attempt landed
  [HIGH  ] DUP003 payments.charge retry c6 after timeout on c5 rotated the idempotency key ('k-1' to 'k-2'), so the server cannot dedupe it
  [MEDIUM] DUP004 payments.charge reused idempotency key 'k-3' with different arguments (c10 then c11)
  [INFO  ] DUP006 deploy_service retry c9 after timeout on c7 was preceded by a verification read
```

## Options

```
--format text|json|md     output format
--fail-on SEVERITY        exit 1 when any finding is at or above SEVERITY (CI gate)
--window SECONDS          ignore duplicates further apart than this (default 3600)
--effect REGEX            override which tool names count as side effects
--read REGEX              override which tool names count as verification reads
--volatile KEY            extra argument key to ignore when comparing (repeatable)
--require-key REGEX       tools that must always carry an idempotency key (repeatable)
--idempotent REGEX        tools that are safe to repeat, e.g. PUT-style upserts (repeatable)
--rules                   list rules
```

## Limits

The verification-read credit is heuristic: any read between the two calls counts, even if it looked at a different resource. Tool classification is name-based, so tune `--effect`, `--read`, and `--idempotent` for your tool catalog.

## Tests

```bash
python3 -m unittest discover -s tests
```

## License

MIT
