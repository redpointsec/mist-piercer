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
