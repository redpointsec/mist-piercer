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
        if ratio >= 0.98:
            return SignalVerdict(
                self.name, Verdict.NOT_DETECTED, "medium",
                f"bodies near-identical (similarity {ratio:.2f}); "
                f"difference likely incidental",
            )
        confidence = "high" if ratio < 0.9 else "medium"
        return SignalVerdict(
            self.name, Verdict.VULNERABLE, confidence,
            f"bodies differ (similarity {ratio:.2f}): "
            f"valid~{v_body[:60]!r} vs nonexistent~{n_body[:60]!r}",
        )
