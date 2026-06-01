# test/test_identify.py
from mpierce.models import HttpExchange
from mpierce.identify import parse_candidates, summarize_exchanges, identify_candidates


def _ex(method, path):
    return HttpExchange(method=method, url=f"https://h{path}", host="h", port=443,
                        protocol="https", path=path, status=200, mimetype="JSON",
                        request_headers={}, request_body="", response_headers={},
                        response_body="", raw_request="", raw_response="")


def test_parse_candidates_valid_json():
    raw = '''[
      {"method":"POST","path":"/login","location":"login",
       "identifier_param":"email","param_location":"form","reason":"login form"}
    ]'''
    cands = parse_candidates(raw, by_path={"/login": _ex("POST", "/login")})
    assert len(cands) == 1
    assert cands[0].identifier_param == "email"
    assert cands[0].url == "https://h/login"


def test_parse_candidates_tolerates_codefence():
    raw = '```json\n[{"method":"POST","path":"/x","location":"other",' \
          '"identifier_param":"u","param_location":"query","reason":"r"}]\n```'
    cands = parse_candidates(raw, by_path={"/x": _ex("POST", "/x")})
    assert cands[0].path == "/x"


def test_parse_candidates_skips_unknown_path():
    raw = '[{"method":"GET","path":"/nope","location":"other",' \
          '"identifier_param":"u","param_location":"query","reason":"r"}]'
    cands = parse_candidates(raw, by_path={"/x": _ex("GET", "/x")})
    assert cands == []


def test_summarize_is_compact():
    summary = summarize_exchanges([_ex("POST", "/login")])
    assert "/login" in summary and "POST" in summary


def test_identify_candidates_uses_injected_llm():
    class FakeLLM:
        def invoke(self, prompt):
            class M:
                content = '[{"method":"POST","path":"/login","location":"login",' \
                          '"identifier_param":"email","param_location":"form","reason":"r"}]'
            return M()
    cands = identify_candidates([_ex("POST", "/login")], llm=FakeLLM())
    assert cands[0].location == "login"
