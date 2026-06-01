# mpierce Enumeration Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `mpierce`, a CLI that identifies enumeration-suspect endpoints from a Burp Suite XML export, extracts valid identifiers, and live-tests endpoints by diffing a known-valid value against a guaranteed-nonexistent one across content, status, explicit, and timing signals.

**Architecture:** A `mpierce/` package with a thin `mpierce.py` argparse entry. The LLM (Bedrock) only *nominates* suspect endpoints and *extracts* identifiers; all vulnerability verdicts come from deterministic Python detectors. Each enumeration signal is an isolated detector behind a common `Detector` protocol + registry. Live HTTP testing is gated behind explicit safeguards (`--confirm`, `--scope`, `--dry-run`, rate limiting).

**Tech Stack:** Python 3.14, `requests`, `rich`, `langchain-aws`/`langchain-core` (Bedrock), `python-dotenv`, `pytest`. Reference spec: `docs/superpowers/specs/2026-05-31-mpierce-enumeration-tool-design.md`.

**Conventions for every task:** run commands from the repo root with the venv active (`source venv/bin/activate`). Run a single test with `pytest test/test_x.py::test_name -v`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `requirements.txt` | dependency pins (new) |
| `.env.example` | documents Bedrock + AWS env vars (new) |
| `mpierce/__init__.py` | package marker |
| `mpierce/models.py` | dataclasses + verdict constants shared everywhere |
| `mpierce/burp.py` | parse Burp XML → `list[HttpExchange]` |
| `mpierce/generate.py` | `random_username` / `random_email` baselines |
| `mpierce/signals/__init__.py` | `Detector` protocol + `DETECTORS` registry |
| `mpierce/signals/status.py` | status-code diff detector |
| `mpierce/signals/content.py` | response-body diff detector |
| `mpierce/signals/explicit.py` | explicit existence-field detector |
| `mpierce/signals/timing.py` | response-timing detector |
| `mpierce/config.py` | env/flag resolution + Bedrock LLM factory |
| `mpierce/identify.py` | LLM endpoint classifier (+ pure JSON parser) |
| `mpierce/extract.py` | LLM identifier extractor (+ pure JSON parser) |
| `mpierce/http_tester.py` | request building, scope safeguard, replay engine |
| `mpierce/report.py` | rich console + JSON report |
| `mpierce/cli.py` | subcommand wiring |
| `mpierce.py` | thin entry → `mpierce.cli.main()` |
| `test/test_*.py` | pytest unit tests |

> **Out of scope for this plan (later phase):** rewriting `CLAUDE.md` and `README.md`. Do not touch them here.

---

## Task 1: Project scaffolding & dependencies

**Files:**
- Create: `requirements.txt`, `.env.example`, `mpierce/__init__.py`, `test/__init__.py`

- [ ] **Step 1: Create `requirements.txt`**

```
langchain-aws
langchain-core
langchain-community
boto3
python-dotenv
requests
rich
pytest
```

- [ ] **Step 2: Create `.env.example`**

```
# LLM configuration (used by identify/extract subcommands)
LLM_PROVIDER=bedrock
LLM_MODEL_ID=qwen.qwen3-next-80b-a3b
LLM_TEMPERATURE=0.2

# AWS Bedrock credentials (us-west-2)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-west-2
```

- [ ] **Step 3: Create empty package markers**

Create `mpierce/__init__.py` containing only:

```python
"""mpierce — enumeration identification & testing tool."""
```

Create `test/__init__.py` as an empty file.

- [ ] **Step 4: Install dependencies**

Run: `source venv/bin/activate && pip install -r requirements.txt`
Expected: installs succeed (most already present in venv).

- [ ] **Step 5: Verify pytest runs**

Run: `source venv/bin/activate && pytest test/ -q`
Expected: "no tests ran" (exit 5) — confirms pytest is wired.

- [ ] **Step 6: Commit**

```bash
git add requirements.txt .env.example mpierce/__init__.py test/__init__.py
git commit -m "chore: scaffold mpierce package and dependencies"
```

---

## Task 2: Shared models & verdict constants

**Files:**
- Create: `mpierce/models.py`
- Test: `test/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_models.py
from mpierce.models import (
    HttpExchange, Candidate, Identifier, Response, SignalVerdict, Finding, Verdict,
)


def test_verdict_constants():
    assert Verdict.VULNERABLE == "VULNERABLE"
    assert Verdict.NOT_DETECTED == "NOT_DETECTED"
    assert Verdict.INCONCLUSIVE == "INCONCLUSIVE"


def test_dataclasses_construct():
    ex = HttpExchange(
        method="GET", url="https://h/x", host="h", port=443, protocol="https",
        path="/x", status=200, mimetype="HTML",
        request_headers={"Host": "h"}, request_body="",
        response_headers={"Server": "x"}, response_body="ok",
        raw_request="GET /x HTTP/1.1", raw_response="HTTP/1.1 200 OK",
    )
    assert ex.host == "h"
    cand = Candidate(method="POST", url="https://h/login", path="/login",
                     location="login", identifier_param="email",
                     param_location="form", reason="why")
    assert cand.identifier_param == "email"
    ident = Identifier(value="a@b.com", type="email", source="/login")
    assert ident.type == "email"
    resp = Response(status=200, headers={}, body="hi", elapsed_ms=12.0, error=None)
    assert resp.elapsed_ms == 12.0
    sv = SignalVerdict(signal="status", verdict=Verdict.VULNERABLE,
                       confidence="high", evidence="200 vs 404")
    finding = Finding(candidate=cand, identifier_param="email",
                      valid_value="a@b.com", nonexistent_value="z@b.com",
                      verdicts=[sv])
    assert finding.verdicts[0].signal == "status"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.models'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/models.py
from dataclasses import dataclass, field
from typing import Optional


class Verdict:
    VULNERABLE = "VULNERABLE"
    NOT_DETECTED = "NOT_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class HttpExchange:
    method: str
    url: str
    host: str
    port: int
    protocol: str
    path: str
    status: Optional[int]
    mimetype: Optional[str]
    request_headers: dict
    request_body: str
    response_headers: dict
    response_body: str
    raw_request: str
    raw_response: str


@dataclass
class Candidate:
    method: str
    url: str
    path: str
    location: str            # login|forgot-password|registration|account-update|account-lookup|lockout|other
    identifier_param: str
    param_location: str      # query|form|json|path
    reason: str


@dataclass
class Identifier:
    value: str
    type: str                # email|username|id
    source: str


@dataclass
class Response:
    status: Optional[int]
    headers: dict
    body: str
    elapsed_ms: float
    error: Optional[str] = None


@dataclass
class SignalVerdict:
    signal: str
    verdict: str
    confidence: str          # high|medium|low
    evidence: str


@dataclass
class Finding:
    candidate: Candidate
    identifier_param: str
    valid_value: str
    nonexistent_value: str
    verdicts: list = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_models.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/models.py test/test_models.py
git commit -m "feat: add shared models and verdict constants"
```

---

## Task 3: Burp XML parser

**Files:**
- Create: `mpierce/burp.py`
- Test: `test/test_burp.py`

Notes on the format (verified against `test/vtm-session.xml`): root `<items>` with `<item>` children; `<url>` is CDATA; `<request>`/`<response>` carry `base64="true|false"`; fields `host`, `port`, `protocol`, `method`, `path`, `status`, `mimetype` (may be empty). The decoded request is a raw HTTP message (`GET / HTTP/1.1\r\n...`).

- [ ] **Step 1: Write the failing test**

```python
# test/test_burp.py
from mpierce.burp import parse_session, _split_http_message


def test_split_http_message_headers_and_body():
    raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
    headers, body = _split_http_message(raw)
    assert headers["Host"] == "h"
    assert headers["Content-Type"] == "application/json"
    assert body == '{"a":1}'


def test_parse_session_real_file():
    exchanges = parse_session("test/vtm-session.xml")
    assert len(exchanges) == 46
    first = exchanges[0]
    assert first.method == "GET"
    assert first.host == "vtm.rdpt.dev"
    assert first.port == 443
    assert first.url == "https://vtm.rdpt.dev/"
    assert first.status == 302
    assert first.raw_request.splitlines()[0] == "GET / HTTP/1.1"
    # the forgot_password POST is present
    assert any(e.method == "POST" and "forgot_password" in e.path for e in exchanges)


def test_parse_session_skips_malformed_items(tmp_path):
    xml = (
        '<items>'
        '<item><url><![CDATA[https://h/ok]]></url><host>h</host><port>443</port>'
        '<protocol>https</protocol><method>GET</method><path>/ok</path>'
        '<status>200</status><mimetype>HTML</mimetype>'
        '<request base64="false">GET /ok HTTP/1.1\r\nHost: h\r\n\r\n</request>'
        '<response base64="false">HTTP/1.1 200 OK\r\n\r\nbody</response></item>'
        '<item><url><![CDATA[https://h/bad]]></url></item>'  # missing fields
        '</items>'
    )
    p = tmp_path / "s.xml"
    p.write_text(xml)
    exchanges = parse_session(str(p))
    assert len(exchanges) == 1
    assert exchanges[0].path == "/ok"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_burp.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.burp'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/burp.py
import base64
import xml.etree.ElementTree as ET
from typing import Optional

from .models import HttpExchange


def _decode(element) -> str:
    if element is None or element.text is None:
        return ""
    if element.attrib.get("base64") == "true":
        return base64.b64decode(element.text).decode("utf-8", "replace")
    return element.text


def _split_http_message(raw: str) -> tuple[dict, str]:
    """Split a raw HTTP message into a headers dict and a body string."""
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    headers: dict = {}
    for line in lines[1:]:  # skip the request/status line
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()
    return headers, body


def _int_or_none(text: Optional[str]) -> Optional[int]:
    try:
        return int(text) if text not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_session(xml_path: str) -> list[HttpExchange]:
    """Parse a Burp Suite session XML export into HttpExchange objects.

    Malformed items (missing required fields) are skipped.
    """
    root = ET.parse(xml_path).getroot()
    exchanges: list[HttpExchange] = []
    for item in root:
        try:
            url = item.find("url").text
            host = item.find("host").text
            method = item.find("method").text
            path = item.find("path").text
            if not (url and host and method and path):
                continue
            raw_request = _decode(item.find("request"))
            raw_response = _decode(item.find("response"))
            req_headers, req_body = _split_http_message(raw_request)
            resp_headers, resp_body = _split_http_message(raw_response)
            mimetype_el = item.find("mimetype")
            exchanges.append(
                HttpExchange(
                    method=method,
                    url=url,
                    host=host,
                    port=_int_or_none(item.find("port").text) or 0,
                    protocol=(item.find("protocol").text or ""),
                    path=path,
                    status=_int_or_none(item.find("status").text),
                    mimetype=(mimetype_el.text if mimetype_el is not None else None),
                    request_headers=req_headers,
                    request_body=req_body,
                    response_headers=resp_headers,
                    response_body=resp_body,
                    raw_request=raw_request,
                    raw_response=raw_response,
                )
            )
        except AttributeError:
            # a required child element was missing → skip this item
            continue
    return exchanges
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_burp.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/burp.py test/test_burp.py
git commit -m "feat: add Burp session XML parser"
```

---

## Task 4: Baseline value generators

**Files:**
- Create: `mpierce/generate.py`
- Test: `test/test_generate.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_generate.py
import re
from mpierce.generate import random_username, random_email


def test_random_username_shape_and_freshness():
    a = random_username("bob")
    b = random_username("bob")
    assert a.startswith("bob")
    assert a != b                       # freshness per call
    assert re.fullmatch(r"bob[0-9a-f]{12}", a)  # name + 12-hex uuid suffix


def test_random_email_shape():
    e = random_email("alice")
    assert re.fullmatch(r"alice[0-9a-f]{12}@example\.com", e)


def test_random_email_custom_domain():
    e = random_email("alice", domain="rdpt.dev")
    assert e.endswith("@rdpt.dev")


def test_default_seed_when_none():
    u = random_username()
    assert re.fullmatch(r"user[0-9a-f]{12}", u)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_generate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.generate'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/generate.py
"""Guaranteed-nonexistent baseline generators.

Pure Python (uuid4) so values are: guaranteed non-existent, fresh per call,
and deterministic in shape (no LLM hallucination).
"""
import uuid


def _suffix() -> str:
    return uuid.uuid4().hex[:12]


def random_username(seed: str = "user") -> str:
    return f"{seed}{_suffix()}"


def random_email(seed: str = "user", domain: str = "example.com") -> str:
    return f"{seed}{_suffix()}@{domain}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_generate.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/generate.py test/test_generate.py
git commit -m "feat: add guaranteed-nonexistent baseline generators"
```

---

## Task 5: Detector protocol & registry

**Files:**
- Create: `mpierce/signals/__init__.py`
- Test: `test/test_signals_registry.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_signals_registry.py
from mpierce.signals import Detector, get_detectors


def test_registry_returns_named_detectors():
    detectors = get_detectors()
    names = {d.name for d in detectors}
    assert names == {"status", "content", "explicit", "timing"}


def test_detectors_conform_to_protocol():
    for d in get_detectors():
        assert isinstance(d.name, str)
        assert callable(d.detect)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_signals_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.signals'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/signals/__init__.py
from typing import Protocol, runtime_checkable

from ..models import Response, SignalVerdict


@runtime_checkable
class Detector(Protocol):
    name: str

    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict:
        ...


def get_detectors() -> list[Detector]:
    """Return one instance of every registered signal detector."""
    from .status import StatusDetector
    from .content import ContentDetector
    from .explicit import ExplicitDetector
    from .timing import TimingDetector

    return [StatusDetector(), ContentDetector(), ExplicitDetector(), TimingDetector()]
```

- [ ] **Step 4: Run test to verify it fails differently**

Run: `pytest test/test_signals_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.signals.status'` (detectors not built yet). This is expected; Tasks 6–9 add them. Proceed to Task 6 before re-running.

- [ ] **Step 5: Commit**

```bash
git add mpierce/signals/__init__.py test/test_signals_registry.py
git commit -m "feat: add detector protocol and registry"
```

---

## Task 6: Status-code detector

**Files:**
- Create: `mpierce/signals/status.py`
- Test: `test/test_signals_status.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_signals_status.py
from mpierce.models import Response, Verdict
from mpierce.signals.status import StatusDetector


def _r(status):
    return Response(status=status, headers={}, body="", elapsed_ms=1.0)


def test_status_split_is_vulnerable():
    d = StatusDetector()
    valid = [_r(200), _r(200), _r(200)]
    nonexistent = [_r(404), _r(404), _r(404)]
    v = d.detect(valid, nonexistent)
    assert v.signal == "status"
    assert v.verdict == Verdict.VULNERABLE
    assert "200" in v.evidence and "404" in v.evidence


def test_same_status_not_detected():
    d = StatusDetector()
    v = d.detect([_r(200), _r(200)], [_r(200), _r(200)])
    assert v.verdict == Verdict.NOT_DETECTED


def test_all_errors_inconclusive():
    d = StatusDetector()
    err = Response(status=None, headers={}, body="", elapsed_ms=0.0, error="timeout")
    v = d.detect([err], [err])
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_signals_status.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.signals.status'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/signals/status.py
from collections import Counter
from typing import Optional

from ..models import Response, SignalVerdict, Verdict


def _dominant_status(responses: list[Response]) -> Optional[int]:
    codes = [r.status for r in responses if r.status is not None]
    if not codes:
        return None
    return Counter(codes).most_common(1)[0][0]


class StatusDetector:
    name = "status"

    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict:
        v_code = _dominant_status(valid)
        n_code = _dominant_status(nonexistent)
        if v_code is None or n_code is None:
            return SignalVerdict(self.name, Verdict.INCONCLUSIVE, "low",
                                 "no successful responses to compare")
        if v_code != n_code:
            return SignalVerdict(
                self.name, Verdict.VULNERABLE, "high",
                f"valid value returns {v_code}, nonexistent returns {n_code}",
            )
        return SignalVerdict(self.name, Verdict.NOT_DETECTED, "high",
                             f"both return {v_code}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_signals_status.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/signals/status.py test/test_signals_status.py
git commit -m "feat: add status-code enumeration detector"
```

---

## Task 7: Content detector

**Files:**
- Create: `mpierce/signals/content.py`
- Test: `test/test_signals_content.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_signals_content.py
from mpierce.models import Response, Verdict
from mpierce.signals.content import ContentDetector, _normalize


def _r(body):
    return Response(status=200, headers={}, body=body, elapsed_ms=1.0)


def test_normalize_strips_volatile_tokens():
    a = _normalize('error <input value="bob"> csrf=abc123 at 2026-01-01T00:00:00')
    b = _normalize('error <input value="alice"> csrf=zzz999 at 2026-02-02T11:11:11')
    assert a == b  # only volatile bits differed


def test_distinct_messages_vulnerable():
    d = ContentDetector()
    valid = [_r("Incorrect password")]
    nonexistent = [_r("User does not exist")]
    v = d.detect(valid, nonexistent)
    assert v.signal == "content"
    assert v.verdict == Verdict.VULNERABLE


def test_identical_messages_not_detected():
    d = ContentDetector()
    v = d.detect([_r("Login failed")], [_r("Login failed")])
    assert v.verdict == Verdict.NOT_DETECTED


def test_empty_bodies_inconclusive():
    d = ContentDetector()
    v = d.detect([_r("")], [_r("")])
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_signals_content.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.signals.content'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/signals/content.py
import difflib
import re
from collections import Counter

from ..models import Response, SignalVerdict, Verdict

# volatile substrings that legitimately differ between requests
_VOLATILE = [
    re.compile(r'value="[^"]*"'),                       # reflected form input
    re.compile(r'csrf[_-]?token["\s:=]+[\w-]+', re.I),  # csrf tokens
    re.compile(r'csrf=[\w-]+', re.I),
    re.compile(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'),  # iso timestamps
    re.compile(r'\b[0-9a-f]{12,}\b', re.I),             # long hex (nonces/uuids)
]


def _normalize(body: str) -> str:
    out = body
    for pattern in _VOLATILE:
        out = pattern.sub("", out)
    return " ".join(out.split())


def _dominant_body(responses: list[Response]) -> str:
    bodies = [_normalize(r.body) for r in responses if r.error is None]
    if not bodies:
        return ""
    return Counter(bodies).most_common(1)[0][0]


class ContentDetector:
    name = "content"

    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict:
        v_body = _dominant_body(valid)
        n_body = _dominant_body(nonexistent)
        if not v_body and not n_body:
            return SignalVerdict(self.name, Verdict.INCONCLUSIVE, "low",
                                 "no comparable response bodies")
        if v_body == n_body:
            return SignalVerdict(self.name, Verdict.NOT_DETECTED, "high",
                                 "normalized response bodies are identical")
        ratio = difflib.SequenceMatcher(None, v_body, n_body).ratio()
        confidence = "high" if ratio < 0.9 else "medium"
        return SignalVerdict(
            self.name, Verdict.VULNERABLE, confidence,
            f"bodies differ (similarity {ratio:.2f}): "
            f"valid~{v_body[:60]!r} vs nonexistent~{n_body[:60]!r}",
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_signals_content.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/signals/content.py test/test_signals_content.py
git commit -m "feat: add content-based enumeration detector"
```

---

## Task 8: Explicit existence-field detector

**Files:**
- Create: `mpierce/signals/explicit.py`
- Test: `test/test_signals_explicit.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_signals_explicit.py
from mpierce.models import Response, Verdict
from mpierce.signals.explicit import ExplicitDetector


def _r(body):
    return Response(status=200, headers={}, body=body, elapsed_ms=1.0)


def test_boolean_field_differs_vulnerable():
    d = ExplicitDetector()
    valid = [_r('{"username_available":false}')]
    nonexistent = [_r('{"username_available":true}')]
    v = d.detect(valid, nonexistent)
    assert v.signal == "explicit"
    assert v.verdict == Verdict.VULNERABLE
    assert "username_available" in v.evidence


def test_phrase_only_in_nonexistent_vulnerable():
    d = ExplicitDetector()
    valid = [_r('{"data":{"users":[{"id":1}]}}')]
    nonexistent = [_r('{"error":"Could not find users in our database"}')]
    v = d.detect(valid, nonexistent)
    assert v.verdict == Verdict.VULNERABLE


def test_no_tells_not_detected():
    d = ExplicitDetector()
    v = d.detect([_r("welcome")], [_r("welcome")])
    assert v.verdict == Verdict.NOT_DETECTED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_signals_explicit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.signals.explicit'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/signals/explicit.py
import re

from ..models import Response, SignalVerdict, Verdict

# (label, compiled pattern). Patterns capture an existence tell.
_TELLS = [
    ("username_available", re.compile(r'username_available["\s:]+(\w+)', re.I)),
    ("available", re.compile(r'"available"["\s:]+(\w+)', re.I)),
    ("exists", re.compile(r'"?exists"?["\s:]+(\w+)', re.I)),
    ("users_null", re.compile(r'"users"\s*:\s*(null|\[)', re.I)),
    ("not_found_phrase", re.compile(r'(could not find|user not found|no account|already in use|already taken|does not exist)', re.I)),
]


def _tells(responses: list[Response]) -> set:
    found = set()
    for r in responses:
        if r.error is not None:
            continue
        for label, pattern in _TELLS:
            m = pattern.search(r.body)
            if m:
                # include the captured group so true/false differences register
                found.add((label, m.group(m.lastindex or 0).lower()))
    return found


class ExplicitDetector:
    name = "explicit"

    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict:
        v_tells = _tells(valid)
        n_tells = _tells(nonexistent)
        diff = v_tells.symmetric_difference(n_tells)
        if diff:
            labels = sorted({label for label, _ in diff})
            return SignalVerdict(
                self.name, Verdict.VULNERABLE, "high",
                f"explicit existence tell(s) differ: {', '.join(labels)}",
            )
        return SignalVerdict(self.name, Verdict.NOT_DETECTED, "high",
                             "no differing explicit existence fields")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_signals_explicit.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/signals/explicit.py test/test_signals_explicit.py
git commit -m "feat: add explicit existence-field detector"
```

---

## Task 9: Timing detector

**Files:**
- Create: `mpierce/signals/timing.py`
- Test: `test/test_signals_timing.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_signals_timing.py
from mpierce.models import Response, Verdict
from mpierce.signals.timing import TimingDetector


def _r(ms):
    return Response(status=200, headers={}, body="", elapsed_ms=ms)


def test_valid_consistently_slower_vulnerable():
    d = TimingDetector()
    valid = [_r(400), _r(420), _r(410), _r(430), _r(405)]
    nonexistent = [_r(40), _r(45), _r(42), _r(38), _r(41)]
    v = d.detect(valid, nonexistent)
    assert v.signal == "timing"
    assert v.verdict == Verdict.VULNERABLE
    assert v.confidence == "low"   # timing is always reported low-confidence


def test_similar_timing_not_detected():
    d = TimingDetector()
    valid = [_r(100), _r(105), _r(98), _r(102), _r(101)]
    nonexistent = [_r(99), _r(101), _r(100), _r(103), _r(97)]
    v = d.detect(valid, nonexistent)
    assert v.verdict == Verdict.NOT_DETECTED


def test_too_few_samples_inconclusive():
    d = TimingDetector()
    v = d.detect([_r(400)], [_r(40)])
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_signals_timing.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.signals.timing'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/signals/timing.py
import statistics

from ..models import Response, SignalVerdict, Verdict

_MIN_SAMPLES = 3
_ABS_DELTA_MS = 50.0   # valid must be at least this much slower (median)
_RATIO = 1.5           # ...and at least this many times slower


def _medians(responses: list[Response]) -> float | None:
    times = [r.elapsed_ms for r in responses if r.error is None and r.elapsed_ms is not None]
    if len(times) < _MIN_SAMPLES:
        return None
    return statistics.median(times)


class TimingDetector:
    name = "timing"

    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict:
        v_med = _medians(valid)
        n_med = _medians(nonexistent)
        if v_med is None or n_med is None:
            return SignalVerdict(self.name, Verdict.INCONCLUSIVE, "low",
                                 f"need >= {_MIN_SAMPLES} clean samples per side")
        delta = v_med - n_med
        ratio = v_med / n_med if n_med > 0 else float("inf")
        if delta >= _ABS_DELTA_MS and ratio >= _RATIO:
            return SignalVerdict(
                self.name, Verdict.VULNERABLE, "low",
                f"valid median {v_med:.0f}ms vs nonexistent {n_med:.0f}ms "
                f"(delta {delta:.0f}ms, {ratio:.1f}x)",
            )
        return SignalVerdict(
            self.name, Verdict.NOT_DETECTED, "low",
            f"timing comparable: valid {v_med:.0f}ms vs nonexistent {n_med:.0f}ms",
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_signals_timing.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Verify the registry test from Task 5 now passes**

Run: `pytest test/test_signals_registry.py -v`
Expected: PASS (2 tests) — all four detectors now importable.

- [ ] **Step 6: Commit**

```bash
git add mpierce/signals/timing.py test/test_signals_timing.py
git commit -m "feat: add timing-based enumeration detector"
```

---

## Task 10: Configuration & LLM factory

**Files:**
- Create: `mpierce/config.py`
- Test: `test/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_config.py
import os
from mpierce.config import Settings


def test_settings_defaults(monkeypatch):
    for var in ("LLM_PROVIDER", "LLM_MODEL_ID", "LLM_TEMPERATURE"):
        monkeypatch.delenv(var, raising=False)
    s = Settings.from_env()
    assert s.provider == "bedrock"
    assert s.model_id == "qwen.qwen3-next-80b-a3b"
    assert s.temperature == 0.2


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("LLM_MODEL_ID", "us.anthropic.claude-3-5-haiku-20241022-v1:0")
    monkeypatch.setenv("LLM_TEMPERATURE", "0.7")
    s = Settings.from_env()
    assert "claude" in s.model_id
    assert s.temperature == 0.7
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.config'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/config.py
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    provider: str = "bedrock"
    model_id: str = "qwen.qwen3-next-80b-a3b"
    temperature: float = 0.2

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            provider=os.getenv("LLM_PROVIDER", "bedrock"),
            model_id=os.getenv("LLM_MODEL_ID", "qwen.qwen3-next-80b-a3b"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
        )


def get_llm(settings: Settings | None = None):
    """Build a LangChain Bedrock chat model. Imported lazily so unit tests
    that only need Settings don't require boto3 credentials."""
    settings = settings or Settings.from_env()
    from langchain_aws import ChatBedrock

    return ChatBedrock(
        model_id=settings.model_id,
        model_kwargs={"temperature": settings.temperature},
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_config.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/config.py test/test_config.py
git commit -m "feat: add configuration and Bedrock LLM factory"
```

---

## Task 11: LLM identify (classifier + pure parser)

**Files:**
- Create: `mpierce/identify.py`
- Test: `test/test_identify.py`

The LLM call is a thin wrapper; the testable unit is `parse_candidates`, which turns the model's JSON into `Candidate` objects. `identify_candidates` accepts an injectable `llm` for mocking.

- [ ] **Step 1: Write the failing test**

```python
# test/test_identify.py
from mpierce.models import HttpExchange
from mpierce.identify import parse_candidates, summarize_exchanges, identify_candidates


def _ex(method, path):
    return HttpExchange(method=method, url=f"https://h{path}", host="h", port=443,
                        protocol="https", path=path, status=200, mimetype="JSON",
                        request_headers={}, request_body="", response_headers={},
                        response_body="", raw_request="", raw_response="")


def test_parse_candidates_valid_json():
    raw = '''[
      {"method":"POST","path":"/login","location":"login",
       "identifier_param":"email","param_location":"form","reason":"login form"}
    ]'''
    cands = parse_candidates(raw, by_path={"/login": _ex("POST", "/login")})
    assert len(cands) == 1
    assert cands[0].identifier_param == "email"
    assert cands[0].url == "https://h/login"


def test_parse_candidates_tolerates_codefence():
    raw = '```json\n[{"method":"POST","path":"/x","location":"other",' \
          '"identifier_param":"u","param_location":"query","reason":"r"}]\n```'
    cands = parse_candidates(raw, by_path={"/x": _ex("POST", "/x")})
    assert cands[0].path == "/x"


def test_parse_candidates_skips_unknown_path():
    raw = '[{"method":"GET","path":"/nope","location":"other",' \
          '"identifier_param":"u","param_location":"query","reason":"r"}]'
    cands = parse_candidates(raw, by_path={"/x": _ex("GET", "/x")})
    assert cands == []


def test_summarize_is_compact():
    summary = summarize_exchanges([_ex("POST", "/login")])
    assert "/login" in summary and "POST" in summary


def test_identify_candidates_uses_injected_llm():
    class FakeLLM:
        def invoke(self, prompt):
            class M:
                content = '[{"method":"POST","path":"/login","location":"login",' \
                          '"identifier_param":"email","param_location":"form","reason":"r"}]'
            return M()
    cands = identify_candidates([_ex("POST", "/login")], llm=FakeLLM())
    assert cands[0].location == "login"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_identify.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.identify'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/identify.py
import json
import re

from .models import Candidate, HttpExchange

_PROMPT = """You are a web application security analyst. Below is a list of HTTP \
requests captured from an application. Identify endpoints that could be vulnerable \
to USER/OBJECT ENUMERATION (where the app leaks whether a username, email, account \
number, or ID exists).

For each suspect endpoint return a JSON array element with keys:
- method: HTTP method
- path: the request path exactly as shown
- location: one of login|forgot-password|registration|account-update|account-lookup|lockout|other
- identifier_param: the request field/param that carries the email/username/id
- param_location: one of query|form|json|path
- reason: short justification

Respond with ONLY a JSON array. Do not judge whether it is vulnerable; only nominate.

Requests:
{summary}
"""


def summarize_exchanges(exchanges: list[HttpExchange]) -> str:
    lines = []
    for e in exchanges:
        body = (e.request_body or "")[:200].replace("\n", " ")
        lines.append(f"{e.method} {e.path} status={e.status} body={body}")
    return "\n".join(lines)


def _strip_codefence(text: str) -> str:
    text = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.S)
    return fence.group(1) if fence else text


def parse_candidates(raw: str, by_path: dict[str, HttpExchange]) -> list[Candidate]:
    """Parse the LLM JSON into Candidate objects, dropping unknown paths."""
    data = json.loads(_strip_codefence(raw))
    candidates: list[Candidate] = []
    seen = set()
    for item in data:
        path = item.get("path")
        method = item.get("method", "GET")
        key = (method, path)
        if path not in by_path or key in seen:
            continue
        seen.add(key)
        ex = by_path[path]
        candidates.append(
            Candidate(
                method=method,
                url=ex.url,
                path=path,
                location=item.get("location", "other"),
                identifier_param=item.get("identifier_param", ""),
                param_location=item.get("param_location", "query"),
                reason=item.get("reason", ""),
            )
        )
    return candidates


def identify_candidates(exchanges: list[HttpExchange], llm=None) -> list[Candidate]:
    if llm is None:
        from .config import get_llm
        llm = get_llm()
    by_path = {e.path: e for e in exchanges}
    prompt = _PROMPT.format(summary=summarize_exchanges(exchanges))
    response = llm.invoke(prompt)
    raw = getattr(response, "content", response)
    return parse_candidates(raw, by_path)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_identify.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/identify.py test/test_identify.py
git commit -m "feat: add LLM endpoint identifier with deterministic parser"
```

---

## Task 12: LLM extract (identifier extraction + pure parser)

**Files:**
- Create: `mpierce/extract.py`
- Test: `test/test_extract.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_extract.py
from mpierce.models import HttpExchange
from mpierce.extract import parse_identifiers, extract_identifiers


def _ex(path, body):
    return HttpExchange(method="POST", url=f"https://h{path}", host="h", port=443,
                        protocol="https", path=path, status=200, mimetype="JSON",
                        request_headers={}, request_body=body, response_headers={},
                        response_body="", raw_request="", raw_response="")


def test_parse_identifiers_dedupes():
    raw = '[{"value":"a@b.com","type":"email","source":"/login"},' \
          '{"value":"a@b.com","type":"email","source":"/login"},' \
          '{"value":"bob","type":"username","source":"/reg"}]'
    idents = parse_identifiers(raw)
    assert len(idents) == 2
    assert {i.value for i in idents} == {"a@b.com", "bob"}


def test_parse_identifiers_tolerates_codefence():
    raw = '```\n[{"value":"x@y.com","type":"email","source":"/a"}]\n```'
    idents = parse_identifiers(raw)
    assert idents[0].type == "email"


def test_extract_identifiers_uses_injected_llm():
    class FakeLLM:
        def invoke(self, prompt):
            class M:
                content = '[{"value":"jl@rdpt.io","type":"email","source":"/login"}]'
            return M()
    idents = extract_identifiers([_ex("/login", "email=jl@rdpt.io")], llm=FakeLLM())
    assert idents[0].value == "jl@rdpt.io"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_extract.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.extract'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/extract.py
import json

from .identify import _strip_codefence, summarize_exchanges
from .models import HttpExchange, Identifier

_PROMPT = """You are a web application security analyst. From the HTTP requests and \
responses below, extract every real USER IDENTIFIER value present (usernames, email \
addresses, account numbers, account IDs). These are known-valid values captured from \
live traffic.

Return ONLY a JSON array of objects with keys:
- value: the identifier string
- type: one of email|username|id
- source: the request path it was found on

Requests:
{summary}
"""


def parse_identifiers(raw: str) -> list[Identifier]:
    data = json.loads(_strip_codefence(raw))
    identifiers: list[Identifier] = []
    seen = set()
    for item in data:
        value = item.get("value")
        if not value or value in seen:
            continue
        seen.add(value)
        identifiers.append(
            Identifier(value=value, type=item.get("type", "id"),
                       source=item.get("source", ""))
        )
    return identifiers


def extract_identifiers(exchanges: list[HttpExchange], llm=None) -> list[Identifier]:
    if llm is None:
        from .config import get_llm
        llm = get_llm()
    prompt = _PROMPT.format(summary=summarize_exchanges(exchanges))
    response = llm.invoke(prompt)
    raw = getattr(response, "content", response)
    return parse_identifiers(raw)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_extract.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/extract.py test/test_extract.py
git commit -m "feat: add LLM identifier extraction with deterministic parser"
```

---

## Task 13: HTTP tester — request building & scope safeguard (no network)

**Files:**
- Create: `mpierce/http_tester.py`
- Test: `test/test_http_tester_build.py`

This task covers the pure, network-free pieces: substituting the identifier value and the scope check. The network replay loop is Task 14.

- [ ] **Step 1: Write the failing test**

```python
# test/test_http_tester_build.py
import pytest
from mpierce.models import HttpExchange, Candidate
from mpierce.http_tester import build_request, in_scope, extract_param_value


def _ex(method, path, body, headers=None, query=""):
    url = f"https://h{path}" + (f"?{query}" if query else "")
    return HttpExchange(method=method, url=url, host="h", port=443, protocol="https",
                        path=path, status=200, mimetype="JSON",
                        request_headers=headers or {}, request_body=body,
                        response_headers={}, response_body="",
                        raw_request="", raw_response="")


def _cand(param, loc, method="POST", path="/login"):
    return Candidate(method=method, url=f"https://h{path}", path=path,
                     location="login", identifier_param=param,
                     param_location=loc, reason="")


def test_extract_param_value_from_form():
    ex = _ex("POST", "/login", "email=jl@rdpt.io&password=x")
    assert extract_param_value(ex, _cand("email", "form")) == "jl@rdpt.io"


def test_extract_param_value_from_json():
    ex = _ex("POST", "/login", '{"email":"jl@rdpt.io","password":"x"}')
    assert extract_param_value(ex, _cand("email", "json")) == "jl@rdpt.io"


def test_extract_param_value_from_query():
    ex = _ex("GET", "/u", "", query="email=jl@rdpt.io")
    assert extract_param_value(ex, _cand("email", "query", "GET", "/u")) == "jl@rdpt.io"


def test_build_request_substitutes_form_body():
    ex = _ex("POST", "/login", "email=jl@rdpt.io&password=x")
    req = build_request(ex, _cand("email", "form"), "zzz@none.com",
                        extra_headers={"Cookie": "s=1"})
    assert req["method"] == "POST"
    assert "zzz@none.com" in req["body"]
    assert "jl@rdpt.io" not in req["body"]
    assert req["headers"]["Cookie"] == "s=1"


def test_build_request_substitutes_query():
    ex = _ex("GET", "/u", "", query="email=jl@rdpt.io")
    req = build_request(ex, _cand("email", "query", "GET", "/u"), "zzz@none.com")
    assert "zzz@none.com" in req["url"]
    assert "jl@rdpt.io" not in req["url"]


def test_in_scope():
    assert in_scope("vtm.rdpt.dev", ["vtm.rdpt.dev"]) is True
    assert in_scope("evil.com", ["vtm.rdpt.dev"]) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_http_tester_build.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.http_tester'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/http_tester.py
import json
import re
import time
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

from .models import Candidate, HttpExchange, Response


def extract_param_value(exchange: HttpExchange, candidate: Candidate) -> str | None:
    """Return the current value of the identifier param in the original request."""
    param = candidate.identifier_param
    loc = candidate.param_location
    if loc == "json":
        try:
            data = json.loads(exchange.request_body or "{}")
            value = data.get(param)
            return str(value) if value is not None else None
        except (ValueError, AttributeError):
            return None
    if loc == "form":
        for k, v in parse_qsl(exchange.request_body or ""):
            if k == param:
                return v
        return None
    if loc == "query":
        q = urlsplit(exchange.url).query
        for k, v in parse_qsl(q):
            if k == param:
                return v
        return None
    if loc == "path":
        return None  # path substitution handled positionally in build_request
    return None


def build_request(exchange: HttpExchange, candidate: Candidate, new_value: str,
                  extra_headers: dict | None = None) -> dict:
    """Build a replay request dict {method,url,headers,body} with the identifier
    param replaced by new_value."""
    headers = dict(exchange.request_headers)
    if extra_headers:
        headers.update(extra_headers)
    url = exchange.url
    body = exchange.request_body or ""
    loc = candidate.param_location
    param = candidate.identifier_param

    if loc == "json":
        try:
            data = json.loads(body or "{}")
            data[param] = new_value
            body = json.dumps(data)
        except ValueError:
            pass
    elif loc == "form":
        pairs = parse_qsl(body)
        pairs = [(k, new_value if k == param else v) for k, v in pairs]
        body = urlencode(pairs)
    elif loc == "query":
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query)
        pairs = [(k, new_value if k == param else v) for k, v in pairs]
        url = urlunsplit(parts._replace(query=urlencode(pairs)))
    elif loc == "path":
        old = extract_param_value(exchange, candidate)
        if old:
            url = url.replace(old, new_value)

    return {"method": candidate.method, "url": url, "headers": headers, "body": body}


def in_scope(host: str, allowed: list[str]) -> bool:
    return host in allowed
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_http_tester_build.py -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/http_tester.py test/test_http_tester_build.py
git commit -m "feat: add request building and scope safeguard"
```

---

## Task 14: HTTP tester — replay engine & test orchestration

**Files:**
- Modify: `mpierce/http_tester.py`
- Test: `test/test_http_tester_replay.py`

Adds: `send_request` (the only function that touches the network, mockable), `replay` (N samples + rate limit), and `test_candidate` (pairs valid vs nonexistent, runs all detectors → `Finding`).

- [ ] **Step 1: Write the failing test**

```python
# test/test_http_tester_replay.py
from mpierce.models import HttpExchange, Candidate, Identifier, Response, Verdict
from mpierce import http_tester


def _ex():
    return HttpExchange(method="POST", url="https://vtm.rdpt.dev/login",
                        host="vtm.rdpt.dev", port=443, protocol="https", path="/login",
                        status=200, mimetype="JSON", request_headers={},
                        request_body="email=jl@rdpt.io&password=x", response_headers={},
                        response_body="", raw_request="", raw_response="")


def _cand():
    return Candidate(method="POST", url="https://vtm.rdpt.dev/login", path="/login",
                     location="login", identifier_param="email",
                     param_location="form", reason="")


def test_replay_collects_samples(monkeypatch):
    calls = []
    def fake_send(req, timeout):
        calls.append(req)
        return Response(status=200, headers={}, body="ok", elapsed_ms=10.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)
    responses = http_tester.replay(_ex(), _cand(), "x@y.com", samples=3, rate=1000)
    assert len(responses) == 3
    assert len(calls) == 3


def test_test_candidate_produces_finding(monkeypatch):
    # valid email → 200 "welcome"; nonexistent → 404 "user not found"
    def fake_send(req, timeout):
        if "jl@rdpt.io" in req["body"]:
            return Response(status=200, headers={}, body="welcome", elapsed_ms=400.0)
        return Response(status=404, headers={}, body="user not found", elapsed_ms=40.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)

    finding = http_tester.test_candidate(
        _ex(), _cand(),
        valid_value="jl@rdpt.io", nonexistent_value="zzz@none.com",
        samples=5, rate=1000,
    )
    signals = {v.signal: v.verdict for v in finding.verdicts}
    assert signals["status"] == Verdict.VULNERABLE
    assert signals["content"] == Verdict.VULNERABLE
    assert finding.valid_value == "jl@rdpt.io"
    assert len(finding.verdicts) == 4   # all detectors ran


def test_dry_run_does_not_send(monkeypatch):
    def boom(req, timeout):
        raise AssertionError("network called during dry run")
    monkeypatch.setattr(http_tester, "send_request", boom)
    planned = http_tester.replay(_ex(), _cand(), "x@y.com", samples=2, rate=1000,
                                 dry_run=True)
    assert planned == []   # dry run returns no responses, sends nothing


def test_reflected_identifier_is_redacted(monkeypatch):
    # the app merely echoes the submitted value; bodies are otherwise identical.
    # after redaction both read "No results for <IDENTIFIER>" → not a real signal.
    def fake_send(req, timeout):
        value = req["body"].split("email=")[1].split("&")[0]
        return Response(status=200, headers={}, body=f"No results for {value}",
                        elapsed_ms=10.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)
    finding = http_tester.test_candidate(
        _ex(), _cand(),
        valid_value="jl@rdpt.io", nonexistent_value="zzz@none.com",
        samples=3, rate=1000,
    )
    signals = {v.signal: v.verdict for v in finding.verdicts}
    assert signals["content"] == Verdict.NOT_DETECTED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_http_tester_replay.py -v`
Expected: FAIL with `AttributeError: module 'mpierce.http_tester' has no attribute 'send_request'`.

- [ ] **Step 3: Append implementation to `mpierce/http_tester.py`**

Add these imports/functions to the existing file (keep everything from Task 13):

```python
import requests  # add to the import block at the top

from .signals import get_detectors  # add near the other mpierce imports
from .models import Finding  # extend the existing models import line


def send_request(req: dict, timeout: float = 10.0) -> Response:
    """The ONLY function that performs network I/O. Mock this in tests."""
    start = time.perf_counter()
    try:
        resp = requests.request(
            req["method"], req["url"], headers=req["headers"],
            data=req["body"] or None, timeout=timeout, allow_redirects=False,
        )
        elapsed = (time.perf_counter() - start) * 1000
        return Response(status=resp.status_code, headers=dict(resp.headers),
                        body=resp.text, elapsed_ms=elapsed)
    except requests.RequestException as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return Response(status=None, headers={}, body="", elapsed_ms=elapsed,
                        error=str(exc))


def replay(exchange: HttpExchange, candidate: Candidate, value: str,
           samples: int = 5, rate: float = 3.0, timeout: float = 10.0,
           extra_headers: dict | None = None, dry_run: bool = False) -> list[Response]:
    """Send the substituted request `samples` times at `rate` req/s.
    In dry_run mode, build the request but send nothing and return []."""
    req = build_request(exchange, candidate, value, extra_headers)
    if dry_run:
        return []
    delay = 1.0 / rate if rate > 0 else 0.0
    responses: list[Response] = []
    for i in range(samples):
        responses.append(send_request(req, timeout))
        if i < samples - 1 and delay:
            time.sleep(delay)
    return responses


def _redact(responses: list[Response], token: str,
            placeholder: str = "<IDENTIFIER>") -> list[Response]:
    """Replace echoes of the injected identifier value in response bodies so
    detectors compare structure/messages, not the reflected value itself.
    Without this, an app that simply echoes the submitted value (e.g.
    "No results for {value}") would make every detector see a body difference
    and report a false positive."""
    if not token:
        return responses
    pattern = re.compile(re.escape(token), re.IGNORECASE)
    return [
        Response(status=r.status, headers=r.headers,
                 body=pattern.sub(placeholder, r.body),
                 elapsed_ms=r.elapsed_ms, error=r.error)
        for r in responses
    ]


def test_candidate(exchange: HttpExchange, candidate: Candidate,
                   valid_value: str, nonexistent_value: str,
                   samples: int = 5, rate: float = 3.0, timeout: float = 10.0,
                   extra_headers: dict | None = None) -> Finding:
    """Replay valid vs nonexistent value and run every detector.

    Each side's response bodies are redacted of the injected identifier value
    so detectors compare structure/messages, not the echoed value itself."""
    valid = _redact(
        replay(exchange, candidate, valid_value, samples, rate, timeout, extra_headers),
        valid_value)
    nonexistent = _redact(
        replay(exchange, candidate, nonexistent_value, samples, rate, timeout, extra_headers),
        nonexistent_value)
    verdicts = [d.detect(valid, nonexistent) for d in get_detectors()]
    return Finding(candidate=candidate, identifier_param=candidate.identifier_param,
                   valid_value=valid_value, nonexistent_value=nonexistent_value,
                   verdicts=verdicts)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_http_tester_replay.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/http_tester.py test/test_http_tester_replay.py
git commit -m "feat: add replay engine and candidate test orchestration"
```

---

## Task 15: Reporting (console + JSON)

**Files:**
- Create: `mpierce/report.py`
- Test: `test/test_report.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_report.py
import json
from mpierce.models import Candidate, SignalVerdict, Finding, Verdict
from mpierce.report import findings_to_dicts, write_json_report, render_console


def _finding():
    cand = Candidate(method="POST", url="https://h/login", path="/login",
                     location="login", identifier_param="email",
                     param_location="form", reason="login form")
    return Finding(candidate=cand, identifier_param="email", valid_value="a@b.com",
                   nonexistent_value="z@none.com",
                   verdicts=[SignalVerdict("status", Verdict.VULNERABLE, "high", "200 vs 404")])


def test_findings_to_dicts_shape():
    d = findings_to_dicts([_finding()])
    assert d[0]["path"] == "/login"
    assert d[0]["valid_value"] == "a@b.com"
    assert d[0]["signals"][0]["signal"] == "status"
    assert d[0]["signals"][0]["verdict"] == "VULNERABLE"


def test_write_json_report(tmp_path):
    out = tmp_path / "report.json"
    write_json_report([_finding()], str(out))
    loaded = json.loads(out.read_text())
    assert loaded[0]["path"] == "/login"


def test_render_console_returns_text():
    text = render_console([_finding()])
    assert "/login" in text
    assert "VULNERABLE" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.report'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/report.py
import json

from rich.console import Console
from rich.table import Table

from .models import Finding, Verdict

_COLOR = {
    Verdict.VULNERABLE: "bold red",
    Verdict.INCONCLUSIVE: "yellow",
    Verdict.NOT_DETECTED: "green",
}


def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    out = []
    for f in findings:
        out.append({
            "method": f.candidate.method,
            "path": f.candidate.path,
            "url": f.candidate.url,
            "location": f.candidate.location,
            "identifier_param": f.identifier_param,
            "valid_value": f.valid_value,
            "nonexistent_value": f.nonexistent_value,
            "signals": [
                {"signal": v.signal, "verdict": v.verdict,
                 "confidence": v.confidence, "evidence": v.evidence}
                for v in f.verdicts
            ],
        })
    return out


def write_json_report(findings: list[Finding], path: str) -> None:
    with open(path, "w") as fh:
        json.dump(findings_to_dicts(findings), fh, indent=2)


def render_console(findings: list[Finding], console: Console | None = None) -> str:
    """Render findings to a rich table and return the text (also prints if console
    given)."""
    capture_console = console or Console(record=True, width=120)
    for f in findings:
        table = Table(title=f"{f.candidate.method} {f.candidate.path}  "
                            f"[{f.candidate.location}] param={f.identifier_param}")
        table.add_column("Signal")
        table.add_column("Verdict")
        table.add_column("Conf.")
        table.add_column("Evidence")
        for v in f.verdicts:
            table.add_row(v.signal,
                          f"[{_COLOR.get(v.verdict, 'white')}]{v.verdict}[/]",
                          v.confidence, v.evidence)
        capture_console.print(table)
    return capture_console.export_text() if console is None else ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_report.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add mpierce/report.py test/test_report.py
git commit -m "feat: add console and JSON reporting"
```

---

## Task 16: CLI wiring & entry point

**Files:**
- Create: `mpierce/cli.py`, `mpierce.py`
- Test: `test/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# test/test_cli.py
import json
import pytest
from mpierce import cli
from mpierce.models import HttpExchange, Candidate, Identifier


def _exchanges():
    return [HttpExchange(method="POST", url="https://vtm.rdpt.dev/login",
            host="vtm.rdpt.dev", port=443, protocol="https", path="/login",
            status=200, mimetype="JSON", request_headers={},
            request_body="email=jl@rdpt.io&password=x", response_headers={},
            response_body="", raw_request="", raw_response="")]


def test_parse_args_subcommands():
    args = cli.build_parser().parse_args(["identify", "-x", "s.xml"])
    assert args.command == "identify"
    assert args.xml == "s.xml"


def test_test_requires_confirm(monkeypatch, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    # candidates/identifiers loaded from files; stub the loaders
    monkeypatch.setattr(cli, "_load_candidates", lambda a, ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    monkeypatch.setattr(cli, "_load_identifiers", lambda a, ex: [
        Identifier("jl@rdpt.io", "email", "/login")])
    rc = cli.main(["test", "-x", "s.xml", "--scope", "vtm.rdpt.dev"])
    assert rc != 0
    assert "confirm" in capsys.readouterr().out.lower()


def test_test_blocks_out_of_scope(monkeypatch, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    monkeypatch.setattr(cli, "_load_candidates", lambda a, ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    monkeypatch.setattr(cli, "_load_identifiers", lambda a, ex: [
        Identifier("jl@rdpt.io", "email", "/login")])
    rc = cli.main(["test", "-x", "s.xml", "--scope", "other.com", "--confirm"])
    assert rc != 0
    assert "scope" in capsys.readouterr().out.lower()


def test_identify_writes_candidates(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    monkeypatch.setattr(cli, "identify_candidates", lambda ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    out = tmp_path / "candidates.json"
    rc = cli.main(["identify", "-x", "s.xml", "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())[0]["path"] == "/login"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mpierce.cli'`.

- [ ] **Step 3: Write minimal implementation**

```python
# mpierce/cli.py
import argparse
import json
import sys

from .burp import parse_session
from .identify import identify_candidates
from .extract import extract_identifiers
from .generate import random_email, random_username
from .http_tester import in_scope, extract_param_value, test_candidate
from .models import Candidate, Identifier
from .report import findings_to_dicts, write_json_report, render_console


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mpierce",
                                     description="Enumeration identification & testing tool")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("-x", "--xml", required=True, help="Burp session XML")

    p_id = sub.add_parser("identify", help="LLM: nominate enumeration-suspect endpoints")
    add_common(p_id)
    p_id.add_argument("--out", default="candidates.json")

    p_ex = sub.add_parser("extract", help="LLM: extract valid identifiers from traffic")
    add_common(p_ex)
    p_ex.add_argument("--out", default="identifiers.json")

    def add_test_flags(p):
        add_common(p)
        p.add_argument("--candidates", help="candidates.json (default: run identify)")
        p.add_argument("--identifiers", help="identifiers.json (default: run extract)")
        p.add_argument("--scope", action="append", default=[],
                       help="allowed host (repeatable)")
        p.add_argument("--header", action="append", default=[],
                       help="extra HTTP header 'Name: Value' (repeatable)")
        p.add_argument("--confirm", action="store_true", help="required to send live HTTP")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--samples", type=int, default=5)
        p.add_argument("--rate", type=float, default=3.0)
        p.add_argument("--timeout", type=float, default=10.0)
        p.add_argument("--output", help="write JSON report to this path")

    p_test = sub.add_parser("test", help="live-test candidates for enumeration")
    add_test_flags(p_test)

    p_run = sub.add_parser("run", help="identify -> extract -> test end to end")
    add_test_flags(p_run)
    return parser


def _parse_headers(header_args: list[str]) -> dict:
    headers = {}
    for h in header_args:
        if ":" in h:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
    return headers


def _load_candidates(args, exchanges) -> list[Candidate]:
    if getattr(args, "candidates", None):
        with open(args.candidates) as fh:
            data = json.load(fh)
        by_path = {e.path: e for e in exchanges}
        out = []
        for c in data:
            ex = by_path.get(c["path"])
            if ex:
                out.append(Candidate(c["method"], ex.url, c["path"], c["location"],
                                     c["identifier_param"], c["param_location"],
                                     c.get("reason", "")))
        return out
    return identify_candidates(exchanges)


def _load_identifiers(args, exchanges) -> list[Identifier]:
    if getattr(args, "identifiers", None):
        with open(args.identifiers) as fh:
            data = json.load(fh)
        return [Identifier(i["value"], i["type"], i.get("source", "")) for i in data]
    return extract_identifiers(exchanges)


def _pick_value(candidate: Candidate, identifiers: list[Identifier],
                exchange) -> tuple[str, str]:
    """Return (valid_value, nonexistent_value) for a candidate."""
    valid = None
    for ident in identifiers:
        if ident.type in ("email", "username") and "@" in ident.value and \
                candidate.location in ("login", "forgot-password", "account-lookup",
                                       "registration", "account-update"):
            valid = ident.value
            break
    if valid is None and identifiers:
        valid = identifiers[0].value
    if valid is None:
        valid = extract_param_value(exchange, candidate) or "test@example.com"
    nonexistent = random_email("test") if "@" in valid else random_username("test")
    return valid, nonexistent


def _run_tests(args, exchanges) -> int:
    candidates = _load_candidates(args, exchanges)
    identifiers = _load_identifiers(args, exchanges)
    by_path = {e.path: e for e in exchanges}

    hosts = {e.host for e in exchanges}
    allowed = args.scope or list(hosts)

    if not args.dry_run and not args.confirm:
        print("Refusing to send live HTTP without --confirm. "
              "Re-run with --confirm (or use --dry-run).")
        return 2

    findings = []
    headers = _parse_headers(args.header)
    for cand in candidates:
        ex = by_path.get(cand.path)
        if ex is None:
            continue
        if not in_scope(ex.host, allowed):
            print(f"Skipping out-of-scope host {ex.host} (not in scope {allowed}).")
            return 3
        valid_value, nonexistent_value = _pick_value(cand, identifiers, ex)
        finding = test_candidate(ex, cand, valid_value, nonexistent_value,
                                 samples=args.samples, rate=args.rate,
                                 timeout=args.timeout, extra_headers=headers)
        findings.append(finding)

    print(render_console(findings))
    if args.output:
        write_json_report(findings, args.output)
        print(f"Wrote report to {args.output}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    exchanges = parse_session(args.xml)

    if args.command == "identify":
        candidates = identify_candidates(exchanges)
        data = [{"method": c.method, "path": c.path, "location": c.location,
                 "identifier_param": c.identifier_param,
                 "param_location": c.param_location, "reason": c.reason}
                for c in candidates]
        with open(args.out, "w") as fh:
            json.dump(data, fh, indent=2)
        for c in candidates:
            print(f"[{c.location}] {c.method} {c.path} param={c.identifier_param} "
                  f"— {c.reason}")
        print(f"Wrote {len(candidates)} candidates to {args.out}")
        return 0

    if args.command == "extract":
        identifiers = extract_identifiers(exchanges)
        data = [{"value": i.value, "type": i.type, "source": i.source}
                for i in identifiers]
        with open(args.out, "w") as fh:
            json.dump(data, fh, indent=2)
        for i in identifiers:
            print(f"{i.type}: {i.value}  (from {i.source})")
        print(f"Wrote {len(identifiers)} identifiers to {args.out}")
        return 0

    if args.command in ("test", "run"):
        return _run_tests(args, exchanges)

    return 1


if __name__ == "__main__":
    sys.exit(main())
```

```python
# mpierce.py  (repo-root thin entry)
import sys

from mpierce.cli import main

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test/test_cli.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Smoke-test the entry point (no network)**

Run: `source venv/bin/activate && python mpierce.py --help && python mpierce.py test --help`
Expected: usage text listing subcommands `identify`, `extract`, `test`, `run` and the test flags (`--confirm`, `--scope`, `--header`, `--dry-run`).

- [ ] **Step 6: Commit**

```bash
git add mpierce/cli.py mpierce.py test/test_cli.py
git commit -m "feat: add CLI subcommands and entry point"
```

---

## Task 17: Remove prototype analyzer scripts

**Files:**
- Delete: `analyzer_authz.py`, `analyzer_extract_users.py`, `analyzer_user_enum.py`

- [ ] **Step 1: Confirm logic is folded in**

`analyzer_extract_users.py` → `mpierce/extract.py`; `analyzer_user_enum.py` → `mpierce/identify.py` + signal detectors; `analyzer_authz.py` was test code (per spec, drop it).

- [ ] **Step 2: Delete the files**

Run: `git rm analyzer_authz.py analyzer_extract_users.py analyzer_user_enum.py`

- [ ] **Step 3: Verify the full suite still passes**

Run: `source venv/bin/activate && pytest test/ -q`
Expected: all tests pass; no import references to the deleted modules.

- [ ] **Step 4: Commit**

```bash
git commit -m "chore: remove prototype analyzer scripts superseded by mpierce"
```

---

## Task 18: Full-suite verification

- [ ] **Step 1: Run the entire test suite**

Run: `source venv/bin/activate && pytest test/ -v`
Expected: every test from Tasks 2–16 passes (no failures, no errors).

- [ ] **Step 2: Dry-run the pipeline against sample data (no network, no LLM)**

Run:
```
source venv/bin/activate && python mpierce.py test -x test/vtm-session.xml \
  --candidates /dev/stdin --identifiers /dev/stdin --scope vtm.rdpt.dev --dry-run <<'EOF'
EOF
```
Note: this is a smoke check that the `test` path builds requests without sending. Because `--dry-run` returns no responses, detectors report INCONCLUSIVE — that's expected. If feeding files is awkward, instead verify `python mpierce.py identify --help` exits 0. The goal is only to confirm wiring, not findings.

- [ ] **Step 3: Final commit (if any uncommitted changes remain)**

```bash
git status
# if clean, nothing to do
```

---

## Self-Review Notes (for the implementer)

- **Spec coverage:** burp parse (T3), identify/extract LLM (T11/T12), generate baselines (T4), four detectors (T6–T9), replay + safeguards `--confirm`/`--scope`/`--dry-run`/`--rate`/`--header` (T13/T14/T16), console+JSON report (T15), config defaulting to `qwen.qwen3-next-80b-a3b` (T10), delete prototypes (T17). CLAUDE.md/README.md intentionally deferred to a later phase.
- **Determinism:** every verdict comes from a deterministic detector; the LLM only nominates/extracts (T11/T12 use injected fakes in tests — no live model needed to pass the suite).
- **Network isolation:** `send_request` is the single network function and is monkeypatched in all replay tests.

---

## Post-Implementation Review Fixes

During subagent-driven execution, code-quality reviews caught issues that corrected the
plan as written. The committed code is authoritative; recorded here so the plan isn't
misleading:

- **Detectors (status/content):** status now returns INCONCLUSIVE when there is no strict
  majority (tie no longer order-dependent). Content judges differences by the changed text
  segments (difflib opcodes) — VULNERABLE when the changed text contains real message
  letters, NOT_DETECTED when the only difference is incidental/non-textual (counters, ids).
  (This superseded an earlier whole-body `ratio >= 0.98` gate, which produced false
  negatives by diluting a short message diff inside a large identical page.)
- **Reflected identifiers (I1):** `http_tester._redact` strips the injected identifier value
  from response bodies before detectors run, preventing reflected-value false positives.
- **Request substitution:** `parse_qsl(..., keep_blank_values=True)` so blank-valued params
  aren't dropped; `path` substitution replaces only the last path segment (via
  urlsplit/urlunsplit) instead of a global `str.replace`, and `extract_param_value` returns
  the last path segment for `path` candidates; `_quote_safe_at` honors the passed `safe` arg
  (`safe + "@"`) so email `@` stays unencoded on Python 3.14.
- **`--dry-run` safety (CRITICAL):** the plan's `test_candidate` omitted `dry_run`, so
  `--dry-run` still sent live HTTP. Fixed: `test_candidate` takes `dry_run` and forwards it
  to both `replay` calls; `_run_tests` passes `dry_run=args.dry_run`. Regression test
  `test_dry_run_sends_no_network` asserts zero network calls.
- **Out-of-scope handling:** out-of-scope candidates are skipped (fail-closed) and the run
  continues; rc 3 only when nothing in scope was tested. `_parse_headers` warns on a
  malformed `--header`; unused `findings_to_dicts` import removed.
