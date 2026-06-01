# test/test_extract.py
from mpierce.models import HttpExchange
from mpierce.extract import parse_identifiers, extract_identifiers


def _ex(path, body):
    return HttpExchange(method="POST", url=f"https://h{path}", host="h", port=443,
                        protocol="https", path=path, status=200, mimetype="JSON",
                        request_headers={}, request_body=body, response_headers={},
                        response_body="", raw_request="", raw_response="")


def test_parse_identifiers_dedupes():
    raw = '[{"value":"a@b.com","type":"email","source":"/login"},' \
          '{"value":"a@b.com","type":"email","source":"/login"},' \
          '{"value":"bob","type":"username","source":"/reg"}]'
    idents = parse_identifiers(raw)
    assert len(idents) == 2
    assert {i.value for i in idents} == {"a@b.com", "bob"}


def test_parse_identifiers_tolerates_codefence():
    raw = '```\n[{"value":"x@y.com","type":"email","source":"/a"}]\n```'
    idents = parse_identifiers(raw)
    assert idents[0].type == "email"


def test_extract_identifiers_uses_injected_llm():
    class FakeLLM:
        def invoke(self, prompt):
            class M:
                content = '[{"value":"jl@rdpt.io","type":"email","source":"/login"}]'
            return M()
    idents = extract_identifiers([_ex("/login", "email=jl@rdpt.io")], llm=FakeLLM())
    assert idents[0].value == "jl@rdpt.io"
