# test/test_signals_status.py
from mpierce.models import Response, Verdict
from mpierce.signals.status import StatusDetector


def _r(status):
    return Response(status=status, headers={}, body="", elapsed_ms=1.0)


def test_status_split_is_vulnerable():
    d = StatusDetector()
    valid = [_r(200), _r(200), _r(200)]
    nonexistent = [_r(404), _r(404), _r(404)]
    v = d.detect(valid, nonexistent)
    assert v.signal == "status"
    assert v.verdict == Verdict.VULNERABLE
    assert "200" in v.evidence and "404" in v.evidence


def test_same_status_not_detected():
    d = StatusDetector()
    v = d.detect([_r(200), _r(200)], [_r(200), _r(200)])
    assert v.verdict == Verdict.NOT_DETECTED


def test_all_errors_inconclusive():
    d = StatusDetector()
    err = Response(status=None, headers={}, body="", elapsed_ms=0.0, error="timeout")
    v = d.detect([err], [err])
    assert v.verdict == Verdict.INCONCLUSIVE
