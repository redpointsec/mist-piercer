# mpierce/http_tester.py
import json
import re
import time
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit, quote

# urlencode passes safe as a positional arg to quote_via; we override it to
# keep '@' unencoded so email-address values remain human-readable in payloads.
_quote_safe_at = lambda s, safe, encoding=None, errors=None: quote(s, safe="@", encoding=encoding, errors=errors)

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
        body = urlencode(pairs, quote_via=_quote_safe_at)
    elif loc == "query":
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query)
        pairs = [(k, new_value if k == param else v) for k, v in pairs]
        url = urlunsplit(parts._replace(query=urlencode(pairs, quote_via=_quote_safe_at)))
    elif loc == "path":
        old = extract_param_value(exchange, candidate)
        if old:
            url = url.replace(old, new_value)

    return {"method": candidate.method, "url": url, "headers": headers, "body": body}


def in_scope(host: str, allowed: list[str]) -> bool:
    return host in allowed
