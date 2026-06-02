# test/test_models.py
from mpierce.models import (
    HttpExchange, Candidate, Identifier, Response, SignalVerdict, Finding, ValueResult, Verdict,
)


def test_verdict_constants():
    assert Verdict.VULNERABLE == "VULNERABLE"
    assert Verdict.NOT_DETECTED == "NOT_DETECTED"
    assert Verdict.INCONCLUSIVE == "INCONCLUSIVE"


def test_dataclasses_construct():
    ex = HttpExchange(
        method="GET", url="https://h/x", host="h", port=443, protocol="https",
        path="/x", status=200, mimetype="HTML",
        request_headers={"Host": "h"}, request_body="",
        response_headers={"Server": "x"}, response_body="ok",
        raw_request="GET /x HTTP/1.1", raw_response="HTTP/1.1 200 OK",
    )
    assert ex.host == "h"
    cand = Candidate(method="POST", url="https://h/login", path="/login",
                     location="login", identifier_param="email",
                     param_location="form", reason="why")
    assert cand.identifier_param == "email"
    ident = Identifier(value="a@b.com", type="email", source="/login")
    assert ident.type == "email"
    resp = Response(status=200, headers={}, body="hi", elapsed_ms=12.0, error=None)
    assert resp.elapsed_ms == 12.0
    sv = SignalVerdict(signal="status", verdict=Verdict.VULNERABLE,
                       confidence="high", evidence="200 vs 404")
    vr = ValueResult(value="a@b.com", verdicts=[sv])
    assert vr.enumerable is True
    finding = Finding(candidate=cand, identifier_param="email",
                      nonexistent_value="z@b.com", results=[vr])
    assert finding.results[0].verdicts[0].signal == "status"
