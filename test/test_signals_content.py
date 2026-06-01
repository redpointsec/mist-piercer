# test/test_signals_content.py
from mpierce.models import Response, Verdict
from mpierce.signals.content import ContentDetector, _normalize


def _r(body):
    return Response(status=200, headers={}, body=body, elapsed_ms=1.0)


def test_normalize_strips_volatile_tokens():
    a = _normalize('error <input value="bob"> csrf=abc123 at 2026-01-01T00:00:00')
    b = _normalize('error <input value="alice"> csrf=zzz999 at 2026-02-02T11:11:11')
    assert a == b  # only volatile bits differed


def test_distinct_messages_vulnerable():
    d = ContentDetector()
    valid = [_r("Incorrect password")]
    nonexistent = [_r("User does not exist")]
    v = d.detect(valid, nonexistent)
    assert v.signal == "content"
    assert v.verdict == Verdict.VULNERABLE


def test_identical_messages_not_detected():
    d = ContentDetector()
    v = d.detect([_r("Login failed")], [_r("Login failed")])
    assert v.verdict == Verdict.NOT_DETECTED


def test_empty_bodies_inconclusive():
    d = ContentDetector()
    v = d.detect([_r("")], [_r("")])
    assert v.verdict == Verdict.INCONCLUSIVE


def test_incidental_numeric_diff_not_detected():
    # large identical page differing only by a numeric counter/id → incidental
    d = ContentDetector()
    big = "the account page is here " * 40
    v = d.detect([_r(big + "01")], [_r(big + "99")])
    assert v.verdict == Verdict.NOT_DETECTED


def test_small_message_in_large_page_detected():
    # the real-world case: a short message differs inside an otherwise
    # identical large page. Must be VULNERABLE regardless of page size.
    d = ContentDetector()
    chrome = "<html><head><title>Account</title></head><body>" + \
             ("<div>navigation and footer filler</div>" * 200)
    valid = [_r(chrome + "<p>Incorrect password</p></body></html>")]
    nonexistent = [_r(chrome + "<p>User not found</p></body></html>")]
    v = d.detect(valid, nonexistent)
    assert v.verdict == Verdict.VULNERABLE
