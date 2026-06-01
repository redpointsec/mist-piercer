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
