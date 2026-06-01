# mpierce/report.py
import json

from rich.console import Console
from rich.table import Table

from .models import Finding, Verdict

_COLOR = {
    Verdict.VULNERABLE: "bold red",
    Verdict.INCONCLUSIVE: "yellow",
    Verdict.NOT_DETECTED: "green",
}


def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    out = []
    for f in findings:
        out.append({
            "method": f.candidate.method,
            "path": f.candidate.path,
            "url": f.candidate.url,
            "location": f.candidate.location,
            "identifier_param": f.identifier_param,
            "valid_value": f.valid_value,
            "nonexistent_value": f.nonexistent_value,
            "signals": [
                {"signal": v.signal, "verdict": v.verdict,
                 "confidence": v.confidence, "evidence": v.evidence}
                for v in f.verdicts
            ],
        })
    return out


def write_json_report(findings: list[Finding], path: str) -> None:
    with open(path, "w") as fh:
        json.dump(findings_to_dicts(findings), fh, indent=2)


def render_console(findings: list[Finding], console: Console | None = None) -> str:
    """Render findings to a rich table and return the text (also prints if console
    given)."""
    capture_console = console or Console(record=True, width=120)
    for f in findings:
        table = Table(title=f"{f.candidate.method} {f.candidate.path}  "
                            f"[{f.candidate.location}] param={f.identifier_param}")
        table.add_column("Signal")
        table.add_column("Verdict")
        table.add_column("Conf.")
        table.add_column("Evidence")
        for v in f.verdicts:
            table.add_row(v.signal,
                          f"[{_COLOR.get(v.verdict, 'white')}]{v.verdict}[/]",
                          v.confidence, v.evidence)
        capture_console.print(table)
    return capture_console.export_text() if console is None else ""
