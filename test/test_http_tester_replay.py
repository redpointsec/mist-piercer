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


def test_test_candidate_produces_finding(monkeypatch):
    # valid email → 200 "welcome"; nonexistent → 404 "user not found"
    def fake_send(req, timeout):
        if "jl@rdpt.io" in req["body"]:
            return Response(status=200, headers={}, body="welcome", elapsed_ms=400.0)
        return Response(status=404, headers={}, body="user not found", elapsed_ms=40.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)

    finding = http_tester.test_candidate(
        _ex(), _cand(),
        valid_value="jl@rdpt.io", nonexistent_value="zzz@none.com",
        samples=5, rate=1000,
    )
    signals = {v.signal: v.verdict for v in finding.verdicts}
    assert signals["status"] == Verdict.VULNERABLE
    assert signals["content"] == Verdict.VULNERABLE
    assert finding.valid_value == "jl@rdpt.io"
    assert len(finding.verdicts) == 4   # all detectors ran


def test_dry_run_does_not_send(monkeypatch):
    def boom(req, timeout):
        raise AssertionError("network called during dry run")
    monkeypatch.setattr(http_tester, "send_request", boom)
    planned = http_tester.replay(_ex(), _cand(), "x@y.com", samples=2, rate=1000,
                                 dry_run=True)
    assert planned == []   # dry run returns no responses, sends nothing


def test_reflected_identifier_is_redacted(monkeypatch):
    # the app merely echoes the submitted value; bodies are otherwise identical.
    # after redaction both read "No results for <IDENTIFIER>" → not a real signal.
    def fake_send(req, timeout):
        value = req["body"].split("email=")[1].split("&")[0]
        return Response(status=200, headers={}, body=f"No results for {value}",
                        elapsed_ms=10.0)
    monkeypatch.setattr(http_tester, "send_request", fake_send)
    finding = http_tester.test_candidate(
        _ex(), _cand(),
        valid_value="jl@rdpt.io", nonexistent_value="zzz@none.com",
        samples=3, rate=1000,
    )
    signals = {v.signal: v.verdict for v in finding.verdicts}
    assert signals["content"] == Verdict.NOT_DETECTED
