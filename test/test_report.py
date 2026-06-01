# test/test_report.py
import json
from mpierce.models import Candidate, SignalVerdict, Finding, Verdict
from mpierce.report import findings_to_dicts, write_json_report, render_console


def _finding():
    cand = Candidate(method="POST", url="https://h/login", path="/login",
                     location="login", identifier_param="email",
                     param_location="form", reason="login form")
    return Finding(candidate=cand, identifier_param="email", valid_value="a@b.com",
                   nonexistent_value="z@none.com",
                   verdicts=[SignalVerdict("status", Verdict.VULNERABLE, "high", "200 vs 404")])


def test_findings_to_dicts_shape():
    d = findings_to_dicts([_finding()])
    assert d[0]["path"] == "/login"
    assert d[0]["valid_value"] == "a@b.com"
    assert d[0]["signals"][0]["signal"] == "status"
    assert d[0]["signals"][0]["verdict"] == "VULNERABLE"


def test_write_json_report(tmp_path):
    out = tmp_path / "report.json"
    write_json_report([_finding()], str(out))
    loaded = json.loads(out.read_text())
    assert loaded[0]["path"] == "/login"


def test_render_console_returns_text():
    text = render_console([_finding()])
    assert "/login" in text
    assert "VULNERABLE" in text


def test_render_console_does_not_write_stdout(capsys):
    text = render_console([_finding()])
    captured = capsys.readouterr()
    assert captured.out == ""       # capture path must NOT write to stdout
    assert "/login" in text         # content is returned instead
    assert "VULNERABLE" in text
