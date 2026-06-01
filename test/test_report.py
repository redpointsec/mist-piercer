# test/test_report.py
import json
from mpierce.models import Candidate, SignalVerdict, Finding, ValueResult, Verdict
from mpierce.report import findings_to_dicts, write_json_report, render_console


def _finding():
    cand = Candidate(method="POST", url="https://h/login", path="/login",
                     location="login", identifier_param="email",
                     param_location="form", reason="login form")
    vr = ValueResult(value="a@b.com",
                     verdicts=[SignalVerdict("status", Verdict.VULNERABLE, "high",
                                             "302 vs 200")])
    return Finding(candidate=cand, identifier_param="email",
                   nonexistent_value="z@none.com", results=[vr])


def test_findings_to_dicts_shape():
    d = findings_to_dicts([_finding()])
    assert d[0]["path"] == "/login"
    assert d[0]["results"][0]["value"] == "a@b.com"
    assert d[0]["results"][0]["enumerable"] is True
    assert d[0]["results"][0]["signals"][0]["verdict"] == "VULNERABLE"


def test_write_json_report(tmp_path):
    out = tmp_path / "report.json"
    write_json_report([_finding()], str(out))
    loaded = json.loads(out.read_text())
    assert loaded[0]["path"] == "/login"
    assert loaded[0]["results"][0]["enumerable"] is True


def test_render_console_returns_text():
    text = render_console([_finding()])
    assert "/login" in text
    assert "a@b.com" in text
    assert "302 vs 200" in text


def test_render_console_does_not_write_stdout(capsys):
    text = render_console([_finding()])
    assert capsys.readouterr().out == ""
    assert "a@b.com" in text
