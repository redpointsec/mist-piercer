# mpierce/extract.py
import json

from .identify import _strip_codefence
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


def _summarize_with_responses(exchanges: list[HttpExchange]) -> str:
    lines = []
    for e in exchanges:
        req = (e.request_body or "")[:150].replace("\n", " ")
        resp = (e.response_body or "")[:150].replace("\n", " ")
        lines.append(f"{e.method} {e.path} status={e.status} req={req} resp={resp}")
    return "\n".join(lines)


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
    prompt = _PROMPT.format(summary=_summarize_with_responses(exchanges))
    response = llm.invoke(prompt)
    raw = getattr(response, "content", response)
    return parse_identifiers(raw)
