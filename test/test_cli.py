# test/test_cli.py
import json
import pytest
from mpierce import cli
from mpierce.models import HttpExchange, Candidate, Identifier


def _exchanges():
    return [HttpExchange(method="POST", url="https://vtm.rdpt.dev/login",
            host="vtm.rdpt.dev", port=443, protocol="https", path="/login",
            status=200, mimetype="JSON", request_headers={},
            request_body="email=jl@rdpt.io&password=x", response_headers={},
            response_body="", raw_request="", raw_response="")]


def test_parse_args_subcommands():
    args = cli.build_parser().parse_args(["identify", "-x", "s.xml"])
    assert args.command == "identify"
    assert args.xml == "s.xml"


def test_test_requires_confirm(monkeypatch, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    # candidates/identifiers loaded from files; stub the loaders
    monkeypatch.setattr(cli, "_load_candidates", lambda a, ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    monkeypatch.setattr(cli, "_load_identifiers", lambda a, ex: [
        Identifier("jl@rdpt.io", "email", "/login")])
    rc = cli.main(["test", "-x", "s.xml", "--scope", "vtm.rdpt.dev"])
    assert rc != 0
    assert "confirm" in capsys.readouterr().out.lower()


def test_test_blocks_out_of_scope(monkeypatch, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    monkeypatch.setattr(cli, "_load_candidates", lambda a, ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    monkeypatch.setattr(cli, "_load_identifiers", lambda a, ex: [
        Identifier("jl@rdpt.io", "email", "/login")])
    rc = cli.main(["test", "-x", "s.xml", "--scope", "other.com", "--confirm"])
    assert rc != 0
    assert "scope" in capsys.readouterr().out.lower()


def test_identify_writes_candidates(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    monkeypatch.setattr(cli, "identify_candidates", lambda ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    out = tmp_path / "candidates.json"
    rc = cli.main(["identify", "-x", "s.xml", "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())[0]["path"] == "/login"
