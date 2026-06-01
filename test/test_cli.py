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


def test_dry_run_sends_no_network(monkeypatch):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    monkeypatch.setattr(cli, "_load_candidates", lambda a, ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    monkeypatch.setattr(cli, "_load_identifiers", lambda a, ex: [
        Identifier("jl@rdpt.io", "email", "/login")])
    from mpierce import http_tester
    def boom(req, timeout=10.0):
        raise AssertionError("network called during --dry-run")
    monkeypatch.setattr(http_tester, "send_request", boom)
    rc = cli.main(["test", "-x", "s.xml", "--scope", "vtm.rdpt.dev", "--dry-run"])
    assert rc == 0   # dry-run completes without calling send_request


def test_identify_writes_candidates(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    monkeypatch.setattr(cli, "identify_candidates", lambda ex: [
        Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                  "email", "form", "r")])
    out = tmp_path / "candidates.json"
    rc = cli.main(["identify", "-x", "s.xml", "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text())[0]["path"] == "/login"


def test_identify_handles_bad_llm_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "parse_session", lambda p: _exchanges())
    def boom(exchanges):
        raise json.JSONDecodeError("bad", "doc", 0)
    monkeypatch.setattr(cli, "identify_candidates", boom)
    rc = cli.main(["identify", "-x", "s.xml", "--out", "/tmp/c.json"])
    assert rc != 0
    assert "json" in capsys.readouterr().out.lower()


def test_pick_value_prefers_original_param_value():
    ex = _exchanges()[0]   # request_body "email=jl@rdpt.io&password=x"
    cand = Candidate("POST", "https://vtm.rdpt.dev/login", "/login", "login",
                     "email", "form", "r")
    valid, nonexistent = cli._pick_value(cand, [], ex)
    assert valid == "jl@rdpt.io"
    assert "@" in nonexistent and nonexistent != valid


def test_pick_value_numeric_baseline_matches_shape():
    ex = HttpExchange(method="GET", url="https://h/user/3901", host="h", port=443,
                      protocol="https", path="/user/3901", status=200, mimetype="JSON",
                      request_headers={}, request_body="", response_headers={},
                      response_body="", raw_request="", raw_response="")
    cand = Candidate("GET", "https://h/user/3901", "/user/3901", "account-lookup",
                     "id", "path", "r")
    valid, nonexistent = cli._pick_value(cand, [], ex)
    assert valid == "3901"
    assert nonexistent.isdigit() and nonexistent != "3901"
