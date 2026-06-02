# mist-piercer (`mpierce`)

**LLM-assisted user/object enumeration testing for web applications.**

Companion tool to the talk *Faces in the Fog — Identifying Users through Unconventional Means* (BSidesVancouver, June 2026 · Redpoint Security).

`mpierce` takes a Burp Suite session XML export and walks the enumeration-testing workflow end to end:

1. **identify** — an LLM nominates endpoints that look prone to enumeration (login, forgot-password, registration, account lookup/update, lockout).
2. **extract** — an LLM harvests valid identifiers (emails, usernames, IDs) already present in the captured traffic.
3. **test** — for each endpoint, every known identifier is replayed alongside a *guaranteed-nonexistent* baseline; any value whose responses differ from the baseline is flagged **enumerable**.

> The LLM only *nominates* and *extracts*. Every vulnerability verdict comes from deterministic Python detectors — there is no code path where the model decides a result.

---

## Enumeration, in one picture

Enumeration is when an app reveals whether a unique value exists. `mpierce` compares a known value against a guaranteed-nonexistent one and looks for a tell across four signals:

| Signal | What it compares |
|--------|------------------|
| **status** | HTTP status codes (e.g. `302` for a real account vs `200` for an unknown one) |
| **content** | response body *messages* ("user not found" vs "incorrect password"), ignoring incidental/volatile text |
| **explicit** | boolean existence fields (`username_available:false`, `users:null`, "already in use") |
| **timing** | response-time differences (valid = slow DB/hash path, missing = fast) — only with `--samples 5+` |

---

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then fill in AWS Bedrock creds
```

The `identify`/`extract` steps call **AWS Bedrock** (LangChain). Configure via `.env`:

```
LLM_PROVIDER=bedrock
LLM_MODEL_ID=qwen.qwen3-next-80b-a3b   # default
LLM_TEMPERATURE=0.2
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-west-2
```

The live `test` step needs **no** LLM or AWS — it only sends HTTP. You can skip Bedrock entirely by supplying `--candidates`/`--identifiers` files (see below).

---

## Usage

```
python mpierce.py <identify|extract|test|run> -x <burp-session.xml> [options]
```

### The pipeline, step by step

```bash
# 1. Which endpoints look enumerable?  -> writes candidates.json
python mpierce.py identify -x test/vtm-session.xml

# 2. What valid identifiers are in the traffic?  -> writes identifiers.json
python mpierce.py extract -x test/vtm-session.xml

# 3. Live-test them (authorized targets only) -> console + JSON report
python mpierce.py test -x test/vtm-session.xml \
    --candidates candidates.json --identifiers identifiers.json \
    --scope vtm.rdpt.dev --confirm --output report.json
```

`run` does all three in one shot (requires Bedrock for the first two stages):

```bash
python mpierce.py run -x test/vtm-session.xml --scope vtm.rdpt.dev --confirm
```

### Preview without sending traffic

```bash
python mpierce.py test -x test/vtm-session.xml \
    --candidates candidates.json --identifiers identifiers.json --dry-run
```

`--dry-run` builds every request but sends nothing (all results report INCONCLUSIVE).

### Authenticated endpoints

No login automation — just paste a session header (repeatable):

```bash
python mpierce.py test ... --header "Cookie: sessionid=..." --header "Authorization: Bearer ..." --confirm
```

---

## Options (`test` / `run`)

| Flag | Default | Purpose |
|------|---------|---------|
| `-x, --xml` | (required) | Burp session XML export |
| `--candidates` | run `identify` | use a candidates.json instead of calling the LLM |
| `--identifiers` | run `extract` | use an identifiers.json instead of calling the LLM |
| `--confirm` | off | **required** before any live request is sent |
| `--dry-run` | off | build requests but send nothing |
| `--scope HOST` | hosts in the XML | allowlist (repeatable); out-of-scope hosts are skipped |
| `--header "N: V"` | — | extra header on every request (repeatable) |
| `--rate` | `3.0` | requests/second throttle |
| `--samples` | `1` | replays per value (set `5+` to enable the timing signal) |
| `--max-values` | `25` | cap on values tested per candidate |
| `--timeout` | `10.0` | per-request timeout (seconds) |
| `--output FILE` | — | write the JSON report |

`identify` and `extract` take `-x` and `--out` (default `candidates.json` / `identifiers.json`).

---

## Safety

`test`/`run` send real HTTP. Guards, all enforced:

- **`--confirm` is mandatory** — without it (and without `--dry-run`) the tool refuses and exits.
- **Scope is fail-closed** — only hosts in `--scope` (or, by default, hosts present in the session file) are touched; anything else is skipped.
- **Throttled** by `--rate`, and capped by `--max-values`.

**Only run live tests against systems you are authorized to test.**

---

## Input / output formats

**candidates.json** — one object per suspect endpoint:
```json
[{"method":"POST","path":"/forgot_password/","location":"forgot-password",
  "identifier_param":"email","param_location":"form","reason":"302 vs 200"}]
```
`param_location` is one of `query | form | json | path`.

**identifiers.json** — known-valid values harvested from traffic. `source` is the endpoint they were seen on (used to scope which values get tested where):
```json
[{"value":"chris@tm.com","type":"email","source":"/forgot_password/"}]
```

**report.json** (`--output`) — per candidate, per value, per signal verdicts:
```json
[{"path":"/forgot_password/","identifier_param":"email",
  "nonexistent_baseline":"test...@example.com",
  "results":[{"value":"chris@tm.com","enumerable":true,
    "signals":[{"signal":"status","verdict":"VULNERABLE","confidence":"high",
                "evidence":"valid value returns 302, nonexistent returns 200"}]}]}]
```

Progress lines are printed to **stderr**; result tables and the report path to **stdout** (so you can `--output` and still watch progress, or pipe stdout cleanly).

---

## Development

```bash
source venv/bin/activate
pytest test/ -q                                   # full suite (no network/LLM needed)
pytest test/test_signals_status.py -v             # a single module
```

The test suite mocks the network and the LLM, so it runs offline with no AWS credentials. See `CLAUDE.md` for architecture and contribution conventions.
