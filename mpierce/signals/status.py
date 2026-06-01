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
