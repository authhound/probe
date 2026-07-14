# `--json` output schema

`authhound-probe radius test --json` and `authhound-probe radsec test --json`
emit a single JSON document to stdout describing every check that ran. This page
is the contract RMM/monitoring scripts can code against.

- **One document per run**, printed once when the run finishes.
- **stdout only.** Human progress text and errors go to stderr; with `--json`
  stdout is pure JSON.
- **No secrets, ever.** Shared secrets, passwords, and full certificates never
  appear in any field — a document is always safe to log, store, or forward.

## Stability guarantee

The top-level `schema_version` is a **major** version (currently `"1"`).

- Within a major version, changes are **additive only**: new fields may be added
  to the document or to a result object, but existing fields never change name,
  type, or meaning, and never disappear. A script that reads only the fields it
  knows keeps working across probe releases.
- A change that would break that (renaming/removing a field, changing a type or
  the meaning of a value) bumps `schema_version` and is called out in the
  release notes.
- New `status` values *could* be added within a major version (treat an
  unknown status as "something to look at"), so switch on the values you know
  and have a default branch. The five current values are listed below.

A golden-file test (`internal/report/json_test.go`) fails CI if the document
shape changes without the golden being regenerated, so a `schema_version` bump
is a deliberate, reviewed act rather than an accident.

## Top-level shape

```json
{
  "schema_version": "1",
  "results": [ /* one object per check, in run order */ ],
  "summary": { "pass": 0, "fail": 0, "warn": 0, "info": 0, "skip": 0 }
}
```

| Field | Type | Presence | Notes |
|---|---|---|---|
| `schema_version` | string | always | Major version of this document shape. Currently `"1"`. |
| `results` | array of result objects | always | One entry per check, in the order they ran. With `--count`, one **aggregate verdict** per check (see the `repeat` block below). |
| `summary` | object | always | Per-status tally. **All five keys are always present**, including zeros — address `.summary.warn` without checking it exists first. |
| `repeat` | object | only with `--count` | Additive: per-iteration results and aggregate statistics for a repeated run. Absent on single runs, whose documents are unchanged. |

### `summary` object

| Field | Type | Notes |
|---|---|---|
| `pass` | integer | Checks that passed. |
| `fail` | integer | Checks that failed. **Drives exit code 1.** |
| `warn` | integer | Works, but something is off (e.g. cert expiring soon). Exit stays `0` unless `--strict`, which makes `warn > 0` exit `1`. |
| `info` | integer | Neutral observations (latency, TLS version). Never affects exit code. |
| `skip` | integer | Checks not run (e.g. no credentials supplied). Never affects exit code. |

## Result object

Each entry in `results`:

| Field | Type | Presence | Notes |
|---|---|---|---|
| `check` | string | always | Stable identifier for the check, e.g. `reachability`, `shared-secret`, `pap`, `peap-mschapv2`, `eap-ttls`, `eap-tls`, `server-cert`, `mtu`, `radsec-connect`, `radsec-tls`, `radsec-cert`, `radsec-radius`. |
| `status` | string | always | One of `pass`, `fail`, `warn`, `info`, `skip` (see below). |
| `summary` | string | always | One plain-English line describing the outcome. |
| `detail` | string | when present | Extra context. Omitted when empty. |
| `hint` | string | when present | Multi-line, paste-ready remediation. Newline formatting is significant. Omitted when empty. Never contains secrets. |
| `fields` | object (string→string) | when present | Structured extras such as `rtt_ms`, `tls_version`, `not_after`, `subject`, `san`, `chain_len`, `source_ip`. `timeout: "true"` marks a request that got no reply at all (a *lost* request, as opposed to a processed rejection). Aggregate verdicts under `--count` add `success_rate`, `attempts`, `successes`, `timeouts`, and `latency_{min,median,p95,max}_ms`. Keys vary by check; values are always strings. Omitted when there are none. |
| `duration_ns` | integer | when present | How long the check took, in nanoseconds. Omitted when zero. |

## `repeat` block (`--count`)

`radius test --count N` runs the checks N times; the document then carries one
**aggregate verdict per check** in `results` (so `summary` and the exit code
reflect the whole run — any failed iteration fails the run), and this block with
the raw material:

```json
"repeat": {
  "count": 10,
  "completed": 10,
  "interval_ms": 2000,
  "requested_interval_ms": 2000,
  "interval_stretched": false,
  "iterations": [ { "results": [ /* result objects, one per check */ ] } ],
  "aggregate": [
    {
      "check": "peap-mschapv2",
      "attempts": 10, "successes": 8, "failures": 2, "timeouts": 2, "skipped": 0,
      "latency_ms": { "min": 9, "median": 12, "p95": 96, "max": 96 }
    }
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `count` | integer | Requested iterations (2–50). |
| `completed` | integer | Iterations that actually finished (lower than `count` after Ctrl-C). |
| `interval_ms` | integer | Pause between iterations actually used. |
| `requested_interval_ms` | integer | The `--interval` that was asked for. |
| `interval_stretched` | boolean | `true` when the requested interval was below the hard-coded safety floor and got stretched. |
| `iterations` | array | One entry per completed iteration, each with its `results` (same result-object shape as the top level). |
| `aggregate` | array | Per-check tallies. `successes` = the server answered and processed the request (pass/warn/info); `timeouts` = the subset of `failures` where no reply arrived at all. `latency_ms` (nearest-rank percentiles over answered runs) is omitted when nothing was answered. |

### `status` values

| Value | Meaning | Effect on exit code |
|---|---|---|
| `pass` | The thing works / is reachable / is valid. | none |
| `fail` | Broken and actionable. | exit `1` |
| `warn` | Works, but something is off (e.g. cert expiring soon). | none by default; exit `1` under `--strict` |
| `info` | Neutral observation. | none |
| `skip` | Not run (e.g. no credentials given). | none |

## Addressing it with `jq`

```sh
# Overall health from the tally (works even with zero of a status):
authhound-probe radius test --server r --json | jq '.summary.fail'

# Did anything warn? (what a scheduled monitor alarms on)
... --json | jq '.summary.warn > 0'

# Per-check status, one line each:
... --json | jq -r '.results[] | "\(.check)\t\(.status)"'

# Just the failing checks and their summaries:
... --json | jq -r '.results[] | select(.status=="fail") | .summary'

# Pin to the schema you coded against:
... --json | jq -e '.schema_version=="1"' >/dev/null || echo "schema changed"

# --count: which checks lost requests, from the aggregate block:
... --count 10 --json | jq -r '.repeat.aggregate[] | select(.timeouts > 0) | "\(.check): \(.timeouts) lost"'
```

## Exit codes

The JSON document and the process exit code are independent surfaces for the same
run — script against whichever is convenient.

| Code | Meaning |
|---|---|
| `0` | All checks passed. Warnings are allowed unless `--strict`. |
| `1` | At least one check `fail`ed — or, under `--strict`, at least one `warn`. |
| `2` | Usage error (bad flags, missing `--server`). No JSON is emitted in this case. |

See the README "Exit codes" section for the same table in prose.
