# mpierce — Enumeration Identification & Testing Tool

**Date:** 2026-05-31
**Status:** Approved for implementation planning
**Companion talk:** *Faces in the Fog — Identifying Users through Unconventional Means* (BSidesVancouver, June 2026)

## Overview

`mpierce` is the demo/working tool for the *Faces in the Fog* talk on **user/object enumeration** — flaws where an application leaks the existence of a unique stored value (email, username, account number, SSN, EIN). It consumes a Burp Suite session XML export and walks the talk's workflow:

1. **Identify** candidate enumeration endpoints (login, forgot-password, registration, account update/lookup, lockout, flexible URL paths).
2. **Extract** valid identifiers (emails / usernames / IDs) from the same captured traffic.
3. **Test** each candidate live by diffing a **known-valid** value against a **guaranteed-nonexistent** value, flagging content / status / explicit / timing tells.

It replaces three throwaway prototype scripts (`analyzer_authz.py`, `analyzer_extract_users.py`, `analyzer_user_enum.py`) with a single, structured CLI.

### Design principle: trustworthy verdicts

The LLM (AWS Bedrock) is used only to **nominate** suspect endpoints and to **extract** identifiers. It never decides whether something is vulnerable. The guaranteed-nonexistent baseline generators are pure Python. All vulnerability verdicts come from deterministic diffing. This mirrors the talk's Tools slide, which calls out *determinism / non-hallucination* as a core value, and keeps the live demo reproducible.

## Goals

- Single CLI entry point (`mpierce.py`) with demoable, chainable subcommands.
- Detect all four enumeration signal types from the talk: content-based, error/status-based, explicit/reflective, timing-based.
- Live HTTP testing with strong safeguards.
- Human-readable console output for the stage + JSON report for evidence.
- Configurable Bedrock model, defaulting to the model the existing analyzers use.

## Non-Goals

- No login-flow automation / credential negotiation. Authenticated testing is handled by letting the user pass an HTTP header (cookie / authorization) that is attached to every replayed request.
- No agentic LLM control of HTTP requests or verdicts in v1 (the `random_*` tools are exposed as LLM-callable for future use, but v1 calls them directly).
- No Burp Intruder / payload-list export in v1 (the tool fires requests itself).
- No support for input formats other than Burp Suite session XML in v1.

## Architecture

### Repository layout

```
mist-piercer/
├── mpierce.py              # thin CLI entry (argparse) → dispatches subcommands
├── mpierce/
│   ├── __init__.py
│   ├── cli.py              # subcommand wiring, shared flags
│   ├── burp.py             # parse Burp XML → list[HttpExchange]
│   ├── models.py           # dataclasses: HttpExchange, Candidate, Identifier, Response, TestResult, Finding
│   ├── identify.py         # LLM: classify which endpoints are enumeration-suspect
│   ├── extract.py          # LLM: pull valid identifiers (emails/usernames/IDs) from traffic
│   ├── generate.py         # random_username / random_email baseline generators (no LLM)
│   ├── http_tester.py      # replay engine + safeguards
│   ├── signals/            # one detector per enumeration type + registry
│   │   ├── __init__.py     # Detector protocol + registry
│   │   ├── content.py
│   │   ├── status.py
│   │   ├── explicit.py
│   │   └── timing.py
│   ├── report.py           # rich console + JSON
│   └── config.py           # env + flag resolution
├── requirements.txt        # NEW
├── .env.example            # NEW
├── test/
│   ├── vtm-session.xml     # existing sample Burp session
│   └── ...                 # pytest unit tests
├── CLAUDE.md
└── README.md
```

### Subcommands

All take `-x/--xml <burp.xml>`.

| Command | Purpose | Side effects |
|---------|---------|--------------|
| `identify` | LLM nominates enumeration-suspect endpoints with location + candidate identifier param. | prints + writes `candidates.json` |
| `extract` | LLM pulls valid identifiers (email/username/ID) from request+response traffic. | prints + writes `identifiers.json` |
| `test` | Live diff engine: pair valid vs generated-nonexistent value, replay, run detectors. | **sends live HTTP** |
| `run` | `identify → extract → test` end-to-end. | sends live HTTP |

### Data flow

```
burp.py: XML → list[HttpExchange]
   ├─ identify.py (LLM) → list[Candidate]   (method+path, location, identifier param)
   └─ extract.py  (LLM) → list[Identifier]  (known-valid values, type, source)
                              │
test: for each Candidate:
   value_valid       = matching Identifier
   value_nonexistent = generate.py random_* (same shape, guaranteed missing)
   for each value: http_tester replays N times → list[Response]
   each signals/ Detector.detect(valid_responses, nonexistent_responses) → SignalVerdict
                              │
report.py → rich console table + report.json (Findings)
```

## Components

### `burp.py` — parser
Owns all Burp XML format quirks. `ET.parse`, iterate `<item>`, read `url` (CDATA), `host`, `port`, `protocol`, `method`, `path`, `status`, `mimetype`; base64-decode `request`/`response` only when the element's `base64="true"`. Emits `HttpExchange` objects. The rest of the tool is format-agnostic.

### `identify.py` — LLM endpoint classifier
Sends the LLM a compact per-exchange summary (method, path, key params, status, response snippet). Asks it to flag enumeration-suspect endpoints, each tagged with a **location** (login / forgot-password / registration / account-update / account-lookup / lockout / other) and the **candidate identifier parameter** (which field carries the email/username/ID). Returns validated structured JSON → `list[Candidate]`. Dedup by method+path. The LLM only nominates; it does not judge vulnerability.

### `extract.py` — LLM identifier extraction
Folds in `analyzer_extract_users.py`. Scans request + response text for real usernames / emails / account-IDs. Returns deduped `list[Identifier]` with `type` and source endpoint. These are the known-valid values for diffing.

### `generate.py` — baseline generators (deterministic)
Implements the talk's Tools slide directly, pure Python via `uuid4` hex:
- `random_username()` → `{name}{uuid-suffix}` (e.g. `bob7f3a9c2d1e4b`)
- `random_email()` → `{name}{uuid-suffix}@{domain}` (e.g. `alice8b4e1f5c9d2a@example.com`)

Properties: **guaranteed non-existence**, **freshness per call**, **determinism / non-hallucination**. The `{name}` seed can mimic the shape of a known-valid identifier so existence is the only variable. Exposed as LLM-callable tools for future agentic use; v1 calls them directly.

### `http_tester.py` — replay engine + safeguards
Given a `Candidate` (endpoint + identifier param) and a value to inject, rebuilds the request from the original `HttpExchange` — preserving method, headers, and body type (form / JSON / query / path) — substitutes the identifier value, and sends via `requests`.

- **Paired sampling:** tests a known-valid value and a generated-nonexistent value, each replayed `N` times (default 5) for timing samples. Records status, headers, body, elapsed time per response.
- **Authenticated testing:** `--header "Name: Value"` (repeatable) is merged onto every replayed request (paste a `Cookie:`/`Authorization:` header from an authenticated session). No login automation.

#### Safeguards
- `--confirm` required before any live request fires.
- `--scope <host>` allowlist; refuses hosts not present in the Burp file or the allowlist.
- `--dry-run` prints the requests it would send without sending.
- `--rate <req/s>` throttle (default conservative, ~3/s).
- `--samples N` (default 5), `--timeout <sec>`.

### `signals/` — detectors (one per enumeration type)
Common interface + registry so `test` runs all enabled detectors and `report` iterates uniformly:

```python
class Detector(Protocol):
    name: str
    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict: ...
```

`SignalVerdict` = verdict (`VULNERABLE` / `NOT_DETECTED` / `INCONCLUSIVE`) + confidence + evidence.

- **content** — diffs response bodies/messages between valid vs nonexistent, normalizing volatile bits (CSRF tokens, timestamps, reflected input). Flags stable differences ("user not found" vs "login failed").
- **status** — compares HTTP status codes (200↔404, 401↔500, …). A consistent split is a signal.
- **explicit** — scans responses for boolean existence tells (`username_available`, `users:null`, `exists:true/false`, "already in use"). Strongest signal when present.
- **timing** — compares response-time distributions; flags when valid is consistently slower than nonexistent beyond a threshold (median delta + simple dispersion check, not a single sample). Reported as **lower-confidence** since it is noise-prone.

Each verdict carries explainable evidence (the diff, the code split, the matched field, the timing numbers).

### `report.py` — output
- **Console (`rich`):** table per candidate endpoint, each signal's verdict color-coded, with confidence and a short evidence line.
- **JSON (`--output report.json`):** structured `Finding`s — endpoint, location, identifier param, per-signal verdicts + evidence, and the exact valid/nonexistent values used.

### `config.py` — configuration
Resolves env + flags. `LLM_PROVIDER`, `LLM_MODEL_ID` (default `qwen.qwen3-next-80b-a3b`), `LLM_TEMPERATURE`; AWS creds via env / `.env` (`load_dotenv()`), matching the existing analyzers and the parent Surveyor platform.

## Error Handling

- **Parsing:** malformed/missing `<item>` fields are skipped with a warning, not fatal; bad base64 logged per-item.
- **LLM:** structured-output validation with retry; on persistent failure, the subcommand reports the error and exits non-zero rather than emitting unvalidated guesses.
- **HTTP:** per-request timeouts, network errors recorded on the `Response` (not crashing the run); a candidate with all-errored responses yields `INCONCLUSIVE`.
- **Safety:** out-of-scope host or missing `--confirm` aborts before any request is sent.

## Testing

pytest unit tests for the network/LLM-free pieces:
- `burp.py` parsing against `test/vtm-session.xml` (CDATA URL, base64 decode, field extraction).
- `generate.py` properties (freshness per call, format/shape, uniqueness).
- each `signals/` detector against synthetic valid/nonexistent `Response` pairs (positive + negative cases).

LLM and live-HTTP paths sit behind thin wrappers so they are mockable; `--dry-run` exercises the request-building path without network.

## Dependencies

New `requirements.txt`: `langchain-aws`, `langchain-core`, `langchain-community`, `boto3`, `python-dotenv`, `requests`, `rich`. New `.env.example` documents `LLM_PROVIDER`, `LLM_MODEL_ID`, `LLM_TEMPERATURE`, and AWS credentials.

## Cleanup & Docs

- Delete `analyzer_authz.py`, `analyzer_extract_users.py`, `analyzer_user_enum.py` after their logic lands in mpierce.
- Update `CLAUDE.md` and rewrite `README.md` to document mpierce: tie to the talk, describe the four enumeration types, the guaranteed-nonexistent baseline concept, the safeguards, and example commands for each subcommand.

## Example Usage

```bash
# 1. What looks enumerable?
python mpierce.py identify -x test/vtm-session.xml

# 2. What valid identifiers are in the traffic?
python mpierce.py extract -x test/vtm-session.xml

# 3. Test live (authorized target), authenticated, dry-run first
python mpierce.py test -x test/vtm-session.xml \
    --scope vtm.rdpt.dev --header "Cookie: session=..." --dry-run
python mpierce.py test -x test/vtm-session.xml \
    --scope vtm.rdpt.dev --header "Cookie: session=..." --confirm --output report.json

# Full pipeline
python mpierce.py run -x test/vtm-session.xml --scope vtm.rdpt.dev --confirm
```
