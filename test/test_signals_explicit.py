# test/test_signals_explicit.py
from mpierce.models import Response, Verdict
from mpierce.signals.explicit import ExplicitDetector


def _r(body):
    return Response(status=200, headers={}, body=body, elapsed_ms=1.0)


def test_boolean_field_differs_vulnerable():
    d = ExplicitDetector()
    valid = [_r('{"username_available":false}')]
    nonexistent = [_r('{"username_available":true}')]
    v = d.detect(valid, nonexistent)
    assert v.signal == "explicit"
    assert v.verdict == Verdict.VULNERABLE
    assert "username_available" in v.evidence


def test_phrase_only_in_nonexistent_vulnerable():
    d = ExplicitDetector()
    valid = [_r('{"data":{"users":[{"id":1}]}}')]
    nonexistent = [_r('{"error":"Could not find users in our database"}')]
    v = d.detect(valid, nonexistent)
    assert v.verdict == Verdict.VULNERABLE


def test_no_tells_not_detected():
    d = ExplicitDetector()
    v = d.detect([_r("welcome")], [_r("welcome")])
    assert v.verdict == Verdict.NOT_DETECTED


def test_no_comparable_responses_inconclusive():
    d = ExplicitDetector()
    v = d.detect([], [])
    assert v.verdict == Verdict.INCONCLUSIVE
