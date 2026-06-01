# mpierce/report.py
import io
import json

from rich.console import Console
from rich.table import Table

from .models import Finding, Verdict


def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    out = []
    for f in findings:
        out.append({
            "method": f.candidate.method,
            "path": f.candidate.path,
            "url": f.candidate.url,
            "location": f.candidate.location,
            "identifier_param": f.identifier_param,
            "nonexistent_baseline": f.nonexistent_value,
            "results": [
                {
                    "value": r.value,
                    "enumerable": r.enumerable,
                    "signals": [
                        {"signal": v.signal, "verdict": v.verdict,
                         "confidence": v.confidence, "evidence": v.evidence}
                        for v in r.verdicts
                    ],
                }
                for r in f.results
            ],
        })
    return out


def write_json_report(findings: list[Finding], path: str) -> None:
    with open(path, "w") as fh:
        json.dump(findings_to_dicts(findings), fh, indent=2)


def render_console(findings: list[Finding], console: Console | None = None) -> str:
    """Render findings to rich tables (one per candidate) and return the text
    (capture path writes to an in-memory buffer, never stdout)."""
    capture_console = console or Console(record=True, width=120, file=io.StringIO())
    for f in findings:
        table = Table(title=f"{f.candidate.method} {f.candidate.path}  "
                            f"[{f.candidate.location}] param={f.identifier_param}  "
                            f"baseline={f.nonexistent_value}")
        table.add_column("Value")
        table.add_column("Enumerable")
        table.add_column("Signals")
        table.add_column("Evidence")
        for r in f.results:
            fired = [v for v in r.verdicts if v.verdict == Verdict.VULNERABLE]
            if r.enumerable:
                table.add_row(r.value, "[bold red]YES[/]",
                              ", ".join(v.signal for v in fired),
                              fired[0].evidence)
            else:
                table.add_row(r.value, "[green]no[/]", "-", "")
        capture_console.print(table)
    return capture_console.export_text() if console is None else ""
