# mpierce/burp.py
import base64
import xml.etree.ElementTree as ET
from typing import Optional

from .models import HttpExchange


def _decode(element) -> str:
    if element is None or element.text is None:
        return ""
    if element.attrib.get("base64") == "true":
        return base64.b64decode(element.text).decode("utf-8", "replace")
    return element.text


def _split_http_message(raw: str) -> tuple[dict, str]:
    """Split a raw HTTP message into a headers dict and a body string."""
    normalized = raw.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    headers: dict = {}
    for line in lines[1:]:  # skip the request/status line
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()
    return headers, body


def _int_or_none(text: Optional[str]) -> Optional[int]:
    try:
        return int(text) if text not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_session(xml_path: str) -> list[HttpExchange]:
    """Parse a Burp Suite session XML export into HttpExchange objects.

    Malformed items (missing required fields) are skipped.
    """
    root = ET.parse(xml_path).getroot()
    exchanges: list[HttpExchange] = []
    for item in root:
        try:
            url = item.find("url").text
            host = item.find("host").text
            method = item.find("method").text
            path = item.find("path").text
            if not (url and host and method and path):
                continue
            raw_request = _decode(item.find("request"))
            raw_response = _decode(item.find("response"))
            req_headers, req_body = _split_http_message(raw_request)
            resp_headers, resp_body = _split_http_message(raw_response)
            mimetype_el = item.find("mimetype")
            exchanges.append(
                HttpExchange(
                    method=method,
                    url=url,
                    host=host,
                    port=_int_or_none(item.find("port").text) or 0,
                    protocol=(item.find("protocol").text or ""),
                    path=path,
                    status=_int_or_none(item.find("status").text),
                    mimetype=(mimetype_el.text if mimetype_el is not None else None),
                    request_headers=req_headers,
                    request_body=req_body,
                    response_headers=resp_headers,
                    response_body=resp_body,
                    raw_request=raw_request,
                    raw_response=raw_response,
                )
            )
        except AttributeError:
            # a required child element was missing → skip this item
            continue
    return exchanges
