# test/test_http_tester_replay.py
from mpierce.models import HttpExchange, Candidate, Identifier, Response, Verdict
from mpierce import http_tester


def _ex():
    return HttpExchange(method="POST", url="https://vtm.rdpt.dev/login",
                        host="vtm.rdpt.dev", port=443, protocol="https", path="/login",
                        status=200, mimetype="JSON", request_headers={},
                        request_body="email=jl@rdpt.io&password=x", response_headers={},
                        response_body="", raw_request="", raw_response="")


def _cand():
    return Candidate(method="POST", url="https://vtm.rdpt.dev/login", path="/login",
                     location="login", identifier_param="email",
                     param_location="form", reason="")


def test_replay_collects_samples(monkeypatch):
    calls = []
    def fake_send(req, timeout):
        calls.append(req)
        return Response(status=200, headers={}, body="ok", elapsed_ms=10.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)
    responses = http_tester.replay(_ex(), _cand(), "x@y.com", samples=3, rate=1000)
    assert len(responses) == 3
    assert len(calls) == 3


def test_test_candidate_flags_enumerable_value(monkeypatch):
    # registered email → 302; everything else → 200 "user not found"
    def fake_send(req, timeout):
        if "jl@rdpt.io" in req["body"]:
            return Response(status=302, headers={}, body="", elapsed_ms=20.0)
        return Response(status=200, headers={}, body="user not found", elapsed_ms=20.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)
    finding = http_tester.test_candidate(
        _ex(), _cand(), known_values=["jl@rdpt.io", "ghost@none.com"],
        nonexistent_value="zzz@none.com", samples=3, rate=1000)
    by_value = {r.value: r for r in finding.results}
    assert by_value["jl@rdpt.io"].enumerable is True       # 302 vs baseline 200
    assert by_value["ghost@none.com"].enumerable is False  # 200 == baseline 200
    assert len(by_value["jl@rdpt.io"].verdicts) == 4       # all detectors ran


def test_dry_run_does_not_send(monkeypatch):
    def boom(req, timeout):
        raise AssertionError("network called during dry run")
    monkeypatch.setattr(http_tester, "send_request", boom)
    planned = http_tester.replay(_ex(), _cand(), "x@y.com", samples=2, rate=1000,
                                 dry_run=True)
    assert planned == []   # dry run returns no responses, sends nothing


def test_reflected_identifier_is_redacted(monkeypatch):
    # app echoes the submitted value; bodies otherwise identical → not enumerable
    def fake_send(req, timeout):
        value = req["body"].split("email=")[1].split("&")[0]
        return Response(status=200, headers={}, body=f"No results for {value}",
                        elapsed_ms=10.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)
    finding = http_tester.test_candidate(
        _ex(), _cand(), known_values=["jl@rdpt.io"],
        nonexistent_value="zzz@none.com", samples=3, rate=1000)
    r = finding.results[0]
    content = next(v for v in r.verdicts if v.signal == "content")
    assert content.verdict == Verdict.NOT_DETECTED
    assert r.enumerable is False


def test_send_request_error_returns_response_with_error(monkeypatch):
    import requests
    def boom(*args, **kwargs):
        raise requests.RequestException("boom")
    monkeypatch.setattr(http_tester.requests, "request", boom)
    r = http_tester.send_request({"method": "GET", "url": "https://x",
                                  "headers": {}, "body": ""})
    assert r.status is None
    assert r.error is not None


def test_redact_matches_whole_token_not_substring():
    # a short value like "foo" must not redact inside "footer"/"food"
    resps = [Response(status=200, headers={}, body="footer foo food", elapsed_ms=1.0)]
    out = http_tester._redact(resps, "foo")
    assert out[0].body == "footer <IDENTIFIER> food"
