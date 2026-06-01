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
