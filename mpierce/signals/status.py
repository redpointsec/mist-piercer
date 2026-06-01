# mpierce/signals/status.py
from collections import Counter
from typing import Optional

from ..models import Response, SignalVerdict, Verdict


def _majority_status(responses: list[Response]) -> Optional[int]:
    """Return the status code only if it holds a STRICT majority of the clean
    responses; otherwise None (no clear signal — likely a flaky endpoint)."""
    codes = [r.status for r in responses if r.status is not None]
    if not codes:
        return None
    code, count = Counter(codes).most_common(1)[0]
    return code if count > len(codes) / 2 else None


class StatusDetector:
    name = "status"

    def detect(self, valid: list[Response], nonexistent: list[Response]) -> SignalVerdict:
        v_code = _majority_status(valid)
        n_code = _majority_status(nonexistent)
        if v_code is None or n_code is None:
            return SignalVerdict(self.name, Verdict.INCONCLUSIVE, "low",
                                 "no clear majority status to compare")
        if v_code != n_code:
            return SignalVerdict(
                self.name, Verdict.VULNERABLE, "high",
                f"valid value returns {v_code}, nonexistent returns {n_code}",
            )
        return SignalVerdict(self.name, Verdict.NOT_DETECTED, "high",
                             f"both return {v_code}")
