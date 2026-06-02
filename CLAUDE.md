# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mist-piercer** is `mpierce` — a CLI that finds **user/object enumeration** flaws (where an app leaks whether a username, email, account number, or ID exists) from a Burp Suite session XML export. It is the companion tool for the talk *Faces in the Fog — Identifying Users through Unconventional Means* (BSidesVancouver, June 2026).

It sits alongside (and prototypes ideas for) the broader Redpoint Surveyor platform — see the parent `../CLAUDE.md`. Similar, more productionized patterns live in that repo's `llm_analysis/` and `SurveyorDynamicAnalysis/`.

User-facing usage lives in `README.md`. This file is the architectural/contributor guide.

## Core Design Principle: trustworthy verdicts

The LLM (AWS Bedrock) is used in **exactly two places** — `identify.py` (nominate suspect endpoints) and `extract.py` (harvest valid identifiers). It **never decides a vulnerability verdict**. Every verdict comes from the deterministic detectors in `signals/`. When changing anything, preserve this boundary: no LLM call may gate a VULNERABLE/NOT_DETECTED result. This is the talk's "determinism / non-hallucination" value and what makes the live demo reproducible.

## The Testing Model (read this before touching the test path)

`mpierce test` does **multi-value comparison**, not "one valid vs one nonexistent":

```
for each candidate endpoint:
    baseline      = responses to a GUARANTEED-NONEXISTENT value (shaped like the param)
    for each KNOWN value (identifiers scoped to this endpoint + the captured param value):
        responses = replay the request with that value injected
        verdicts  = every detector.detect(responses, baseline)
        value is "enumerable" if ANY detector says VULNERABLE
```

Why this shape: harvested identifiers are a *mix* of valid and invalid, and the captured form value is often junk (e.g. a tester's throwaway email on a forgot-password probe). Comparing each known value to a known-nonexistent baseline sidesteps "which value is valid?" entirely — a registered email returning `302` vs the baseline's `200` is the signal; an unregistered one matching the baseline simply isn't flagged.

Two correctness safeguards in this path:
- **Endpoint scoping** (`_pick_values` in `cli.py`): a candidate is tested only against identifiers whose `source` is that endpoint (falling back to shape-compatible ones). Without this, every endpoint gets tested against every identifier — combinatorial traffic that also trips target rate-limiting.
- **Identifier redaction** (`_redact` in `http_tester.py`): the injected value is stripped from response bodies (on word boundaries) *before* detection, so an app that merely echoes the submitted value doesn't manufacture a content difference.

## Architecture

| File | Responsibility |
|------|----------------|
| `mpierce.py` | thin entry → `mpierce.cli.main()` |
| `mpierce/cli.py` | argparse subcommands, value selection (`_pick_values`), exchange resolution (`_resolve_exchange`), the test loop + safeguards |
| `mpierce/burp.py` | parse Burp XML → `list[HttpExchange]` (owns all format quirks) |
| `mpierce/models.py` | dataclasses + `Verdict` constants shared everywhere |
| `mpierce/identify.py` | LLM endpoint classifier + pure JSON parser |
| `mpierce/extract.py` | LLM identifier extractor + pure JSON parser |
| `mpierce/generate.py` | `random_username` / `random_email` / `random_numeric` baselines (pure Python, no LLM) |
| `mpierce/http_tester.py` | request building, scope check, replay engine, `_redact`, `test_candidate` |
| `mpierce/signals/` | `Detector` protocol + registry, and one detector per enumeration type |
| `mpierce/report.py` | rich console tables + JSON report |
| `mpierce/config.py` | env/flag resolution + lazy Bedrock LLM factory |

### Data flow

```
burp.parse_session(xml) -> list[HttpExchange]
   identify.identify_candidates (LLM)  -> list[Candidate]
   extract.extract_identifiers  (LLM)  -> list[Identifier]
        -> cli._run_tests: per candidate, _pick_values -> http_tester.test_candidate
             -> replay (live HTTP) -> _redact -> signals detectors -> Finding(results=[ValueResult...])
        -> report (console + JSON)
```

### The four signal detectors (`mpierce/signals/`)

Each conforms to the `Detector` protocol: a `name` attribute and `detect(valid, nonexistent) -> SignalVerdict`, registered in `signals/__init__.py:get_detectors()`. "valid" here is a known value's responses; "nonexistent" is the baseline. A VULNERABLE verdict means "this value's responses differ from a guaranteed-nonexistent value → the app reveals it."

- **status** — dominant status code, requiring a strict majority (ties → INCONCLUSIVE, not order-dependent).
- **content** — compares the *changed text segments* (`difflib` opcodes) after stripping volatile tokens (reflected input, CSRF, timestamps, long hex). Flags only substantive textual differences, so a short message diff inside a large identical page still registers and incidental/numeric diffs do not. (Do NOT reintroduce a whole-body similarity ratio gate — it diluted small messages into false negatives.)
- **explicit** — differing boolean existence fields / phrases (`username_available`, `users:null`, "already in use", "not found"). INCONCLUSIVE when there are no comparable responses.
- **timing** — median response-time delta gated on BOTH an absolute threshold and a ratio; always low-confidence; needs `--samples >= 3`.

## Burp Session XML Format

`test/vtm-session.xml` is a Burp export (`burpVersion="2025.1.4"`, 46 items) used as sample data **and** as the fixture in `test/test_burp.py`. Each `<item>` has `url` (CDATA), `host`, `port`, `protocol`, `method`, `path`, `status`, `mimetype`, and `request`/`response` (base64-decode only when `base64="true"`). The decoded request is a raw HTTP message. A path can appear multiple times (GET form page + POST submission), so resolve candidates by **(method, path)** preferring a body-bearing request — keying on path alone picks the wrong one.

## Commands

```bash
source venv/bin/activate          # Python 3.14 venv
pip install -r requirements.txt

pytest test/ -q                                   # full suite (offline; network + LLM are mocked)
pytest test/test_signals_content.py::test_small_message_in_large_page_detected -v   # single test

python mpierce.py identify -x test/vtm-session.xml          # LLM (needs Bedrock)
python mpierce.py test -x test/vtm-session.xml \           # live (no LLM)
    --candidates candidates.json --identifiers identifiers.json \
    --scope vtm.rdpt.dev --confirm --output report.json
```

Exit codes: `0` ok · `2` live test without `--confirm` · `3` no in-scope candidates · `4` malformed LLM/JSON input.

LLM config via `.env` (`LLM_PROVIDER`, `LLM_MODEL_ID` default `qwen.qwen3-next-80b-a3b`, `LLM_TEMPERATURE`) + AWS Bedrock creds in `us-west-2`.

## Testing Conventions

- **TDD**: write the failing test first; the suite must stay green and must not require network or AWS credentials. `http_tester.send_request` is the single network chokepoint — monkeypatch it; `config.get_llm` is imported lazily so unit tests never touch boto3.
- Detectors are tested against synthetic `Response` pairs; the parser against `test/vtm-session.xml`.
- When verifying live behavior, only target authorized hosts, keep `--rate` low, and prefer a small `--candidates`/`--identifiers` set — large unscoped runs trip target rate-limiting and produce uniform (all NOT_DETECTED) results.

## Workflow Rules (inherited from the parent repo)

- **Never push directly to `main`.** Branch, commit, open a PR, and let the user confirm the merge.
- End commit messages with `Co-Authored-By: WOZCODE <contact@withwoz.com>`.
- Design docs and implementation plans live under `docs/superpowers/`.

## Deferred / Future Work

- **Static (offline) detection**: diff the captured response pairs already in the XML (a registered vs unregistered value with differing responses) — detects enumeration with zero live traffic, independent of current target state. Scaffolding/insight exists; not yet implemented.
