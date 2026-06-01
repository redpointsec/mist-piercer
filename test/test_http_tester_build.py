# test/test_http_tester_build.py
import pytest
from mpierce.models import HttpExchange, Candidate
from mpierce.http_tester import build_request, in_scope, extract_param_value


def _ex(method, path, body, headers=None, query=""):
    url = f"https://h{path}" + (f"?{query}" if query else "")
    return HttpExchange(method=method, url=url, host="h", port=443, protocol="https",
                        path=path, status=200, mimetype="JSON",
                        request_headers=headers or {}, request_body=body,
                        response_headers={}, response_body="",
                        raw_request="", raw_response="")


def _cand(param, loc, method="POST", path="/login"):
    return Candidate(method=method, url=f"https://h{path}", path=path,
                     location="login", identifier_param=param,
                     param_location=loc, reason="")


def test_extract_param_value_from_form():
    ex = _ex("POST", "/login", "email=jl@rdpt.io&password=x")
    assert extract_param_value(ex, _cand("email", "form")) == "jl@rdpt.io"


def test_extract_param_value_from_json():
    ex = _ex("POST", "/login", '{"email":"jl@rdpt.io","password":"x"}')
    assert extract_param_value(ex, _cand("email", "json")) == "jl@rdpt.io"


def test_extract_param_value_from_query():
    ex = _ex("GET", "/u", "", query="email=jl@rdpt.io")
    assert extract_param_value(ex, _cand("email", "query", "GET", "/u")) == "jl@rdpt.io"


def test_build_request_substitutes_form_body():
    ex = _ex("POST", "/login", "email=jl@rdpt.io&password=x")
    req = build_request(ex, _cand("email", "form"), "zzz@none.com",
                        extra_headers={"Cookie": "s=1"})
    assert req["method"] == "POST"
    assert "zzz@none.com" in req["body"]
    assert "jl@rdpt.io" not in req["body"]
    assert req["headers"]["Cookie"] == "s=1"


def test_build_request_substitutes_query():
    ex = _ex("GET", "/u", "", query="email=jl@rdpt.io")
    req = build_request(ex, _cand("email", "query", "GET", "/u"), "zzz@none.com")
    assert "zzz@none.com" in req["url"]
    assert "jl@rdpt.io" not in req["url"]


def test_in_scope():
    assert in_scope("vtm.rdpt.dev", ["vtm.rdpt.dev"]) is True
    assert in_scope("evil.com", ["vtm.rdpt.dev"]) is False


import json as _json
from mpierce.models import Candidate as _Candidate


def _path_cand():
    return _Candidate(method="GET", url="https://h/users/joe", path="/users/joe",
                      location="account-lookup", identifier_param="user",
                      param_location="path", reason="")


def test_extract_param_value_from_path():
    ex = _ex("GET", "/users/joe", "")
    assert extract_param_value(ex, _path_cand()) == "joe"


def test_build_request_substitutes_path_segment():
    ex = _ex("GET", "/users/joe", "")
    req = build_request(ex, _path_cand(), "zzznope")
    assert req["url"].endswith("/users/zzznope")
    assert "joe" not in req["url"]


def test_path_substitution_leaves_query_untouched():
    ex = _ex("GET", "/users/joe", "", query="ref=joe")
    cand = _Candidate(method="GET", url="https://h/users/joe?ref=joe",
                      path="/users/joe", location="account-lookup",
                      identifier_param="user", param_location="path", reason="")
    req = build_request(ex, cand, "zzznope")
    assert "/users/zzznope" in req["url"]
    assert "ref=joe" in req["url"]   # query's "joe" must NOT be clobbered


def test_build_request_substitutes_blank_form_value():
    ex = _ex("POST", "/login", "email=&password=x")
    req = build_request(ex, _cand("email", "form"), "zzz@none.com")
    assert "zzz@none.com" in req["body"]   # blank value still substituted
    assert "password=x" in req["body"]


def test_build_request_substitutes_json_body():
    ex = _ex("POST", "/login", '{"email":"jl@rdpt.io","password":"x"}')
    req = build_request(ex, _cand("email", "json"), "zzz@none.com")
    assert _json.loads(req["body"])["email"] == "zzz@none.com"
    assert _json.loads(req["body"])["password"] == "x"
