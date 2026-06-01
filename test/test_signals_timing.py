# test/test_signals_timing.py
from mpierce.models import Response, Verdict
from mpierce.signals.timing import TimingDetector


def _r(ms):
    return Response(status=200, headers={}, body="", elapsed_ms=ms)


def test_valid_consistently_slower_vulnerable():
    d = TimingDetector()
    valid = [_r(400), _r(420), _r(410), _r(430), _r(405)]
    nonexistent = [_r(40), _r(45), _r(42), _r(38), _r(41)]
    v = d.detect(valid, nonexistent)
    assert v.signal == "timing"
    assert v.verdict == Verdict.VULNERABLE
    assert v.confidence == "low"   # timing is always reported low-confidence


def test_similar_timing_not_detected():
    d = TimingDetector()
    valid = [_r(100), _r(105), _r(98), _r(102), _r(101)]
    nonexistent = [_r(99), _r(101), _r(100), _r(103), _r(97)]
    v = d.detect(valid, nonexistent)
    assert v.verdict == Verdict.NOT_DETECTED


def test_too_few_samples_inconclusive():
    d = TimingDetector()
    v = d.detect([_r(400)], [_r(40)])
    assert v.verdict == Verdict.INCONCLUSIVE
