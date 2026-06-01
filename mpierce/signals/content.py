# mpierce/signals/content.py
import difflib
import re
from collections import Counter

from ..models import Response, SignalVerdict, Verdict

_MIN_DIFF_LETTERS = 3   # changed text needs this many letters to count as a real message

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


def _diff_text(a: str, b: str) -> str:
    """Concatenate only the segments that differ between a and b, so the
    verdict depends on WHAT changed, not on how large the identical
    surrounding page is."""
    matcher = difflib.SequenceMatcher(None, a, b)
    parts = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag != "equal":
            parts.append(a[i1:i2])
            parts.append(b[j1:j2])
    return " ".join(p for p in parts if p)


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
        diff = _diff_text(v_body, n_body)
        letters = re.sub(r"[^A-Za-z]", "", diff)
        if len(letters) < _MIN_DIFF_LETTERS:
            return SignalVerdict(
                self.name, Verdict.NOT_DETECTED, "medium",
                f"only incidental (non-textual) differences: {diff[:60]!r}",
            )
        return SignalVerdict(
            self.name, Verdict.VULNERABLE, "high",
            f"response content differs in text: {diff[:120]!r}",
        )
