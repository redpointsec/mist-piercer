# mpierce/http_tester.py
import json
import re
import time
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit, quote

import requests

# urlencode passes safe as a positional arg to quote_via; we override it to
# keep '@' unencoded so email-address values remain human-readable in payloads.
_quote_safe_at = lambda s, safe, encoding=None, errors=None: quote(s, safe=safe + "@", encoding=encoding, errors=errors)

from .models import Candidate, Finding, HttpExchange, Response
from .signals import get_detectors


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
        for k, v in parse_qsl(exchange.request_body or "", keep_blank_values=True):
            if k == param:
                return v
        return None
    if loc == "query":
        q = urlsplit(exchange.url).query
        for k, v in parse_qsl(q, keep_blank_values=True):
            if k == param:
                return v
        return None
    if loc == "path":
        segments = [s for s in urlsplit(exchange.url).path.split("/") if s]
        return segments[-1] if segments else None
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
        pairs = parse_qsl(body, keep_blank_values=True)
        pairs = [(k, new_value if k == param else v) for k, v in pairs]
        body = urlencode(pairs, quote_via=_quote_safe_at)
    elif loc == "query":
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs = [(k, new_value if k == param else v) for k, v in pairs]
        url = urlunsplit(parts._replace(query=urlencode(pairs, quote_via=_quote_safe_at)))
    elif loc == "path":
        parts = urlsplit(url)
        segments = parts.path.split("/")
        for idx in range(len(segments) - 1, -1, -1):
            if segments[idx]:                 # replace the last non-empty segment only
                segments[idx] = new_value
                break
        url = urlunsplit(parts._replace(path="/".join(segments)))

    return {"method": candidate.method, "url": url, "headers": headers, "body": body}


def in_scope(host: str, allowed: list[str]) -> bool:
    return host in allowed


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
                   extra_headers: dict | None = None, dry_run: bool = False) -> Finding:
    """Replay valid vs nonexistent value and run every detector.

    Each side's response bodies are redacted of the injected identifier value
    so detectors compare structure/messages, not the echoed value itself.
    When dry_run is True, replay sends nothing and returns [], so every detector
    reports INCONCLUSIVE."""
    valid = _redact(
        replay(exchange, candidate, valid_value, samples, rate, timeout,
               extra_headers, dry_run=dry_run),
        valid_value)
    nonexistent = _redact(
        replay(exchange, candidate, nonexistent_value, samples, rate, timeout,
               extra_headers, dry_run=dry_run),
        nonexistent_value)
    verdicts = [d.detect(valid, nonexistent) for d in get_detectors()]
    return Finding(candidate=candidate, identifier_param=candidate.identifier_param,
                   valid_value=valid_value, nonexistent_value=nonexistent_value,
                   verdicts=verdicts)
