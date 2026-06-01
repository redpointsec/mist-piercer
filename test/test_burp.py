# test/test_burp.py
from mpierce.burp import parse_session, _split_http_message


def test_split_http_message_headers_and_body():
    raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
    headers, body = _split_http_message(raw)
    assert headers["Host"] == "h"
    assert headers["Content-Type"] == "application/json"
    assert body == '{"a":1}'


def test_parse_session_real_file():
    exchanges = parse_session("test/vtm-session.xml")
    assert len(exchanges) == 46
    first = exchanges[0]
    assert first.method == "GET"
    assert first.host == "vtm.rdpt.dev"
    assert first.port == 443
    assert first.url == "https://vtm.rdpt.dev/"
    assert first.status == 302
    assert first.raw_request.splitlines()[0] == "GET / HTTP/1.1"
    # the forgot_password POST is present
    assert any(e.method == "POST" and "forgot_password" in e.path for e in exchanges)


def test_parse_session_skips_malformed_items(tmp_path):
    xml = (
        '<items>'
        '<item><url><![CDATA[https://h/ok]]></url><host>h</host><port>443</port>'
        '<protocol>https</protocol><method>GET</method><path>/ok</path>'
        '<status>200</status><mimetype>HTML</mimetype>'
        '<request base64="false">GET /ok HTTP/1.1\r\nHost: h\r\n\r\n</request>'
        '<response base64="false">HTTP/1.1 200 OK\r\n\r\nbody</response></item>'
        '<item><url><![CDATA[https://h/bad]]></url></item>'  # missing fields
        '</items>'
    )
    p = tmp_path / "s.xml"
    p.write_text(xml)
    exchanges = parse_session(str(p))
    assert len(exchanges) == 1
    assert exchanges[0].path == "/ok"
