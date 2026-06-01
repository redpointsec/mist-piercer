# mpierce/cli.py
import argparse
import json
import sys

from .burp import parse_session
from .identify import identify_candidates
from .extract import extract_identifiers
from .generate import random_email, random_username
from .http_tester import in_scope, extract_param_value, test_candidate
from .models import Candidate, Identifier
from .report import findings_to_dicts, write_json_report, render_console


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mpierce",
                                     description="Enumeration identification & testing tool")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("-x", "--xml", required=True, help="Burp session XML")

    p_id = sub.add_parser("identify", help="LLM: nominate enumeration-suspect endpoints")
    add_common(p_id)
    p_id.add_argument("--out", default="candidates.json")

    p_ex = sub.add_parser("extract", help="LLM: extract valid identifiers from traffic")
    add_common(p_ex)
    p_ex.add_argument("--out", default="identifiers.json")

    def add_test_flags(p):
        add_common(p)
        p.add_argument("--candidates", help="candidates.json (default: run identify)")
        p.add_argument("--identifiers", help="identifiers.json (default: run extract)")
        p.add_argument("--scope", action="append", default=[],
                       help="allowed host (repeatable)")
        p.add_argument("--header", action="append", default=[],
                       help="extra HTTP header 'Name: Value' (repeatable)")
        p.add_argument("--confirm", action="store_true", help="required to send live HTTP")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--samples", type=int, default=5)
        p.add_argument("--rate", type=float, default=3.0)
        p.add_argument("--timeout", type=float, default=10.0)
        p.add_argument("--output", help="write JSON report to this path")

    p_test = sub.add_parser("test", help="live-test candidates for enumeration")
    add_test_flags(p_test)

    p_run = sub.add_parser("run", help="identify -> extract -> test end to end")
    add_test_flags(p_run)
    return parser


def _parse_headers(header_args: list[str]) -> dict:
    headers = {}
    for h in header_args:
        if ":" in h:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
    return headers


def _load_candidates(args, exchanges) -> list[Candidate]:
    if getattr(args, "candidates", None):
        with open(args.candidates) as fh:
            data = json.load(fh)
        by_path = {e.path: e for e in exchanges}
        out = []
        for c in data:
            ex = by_path.get(c["path"])
            if ex:
                out.append(Candidate(c["method"], ex.url, c["path"], c["location"],
                                     c["identifier_param"], c["param_location"],
                                     c.get("reason", "")))
        return out
    return identify_candidates(exchanges)


def _load_identifiers(args, exchanges) -> list[Identifier]:
    if getattr(args, "identifiers", None):
        with open(args.identifiers) as fh:
            data = json.load(fh)
        return [Identifier(i["value"], i["type"], i.get("source", "")) for i in data]
    return extract_identifiers(exchanges)


def _pick_value(candidate: Candidate, identifiers: list[Identifier],
                exchange) -> tuple[str, str]:
    """Return (valid_value, nonexistent_value) for a candidate."""
    valid = None
    for ident in identifiers:
        if ident.type in ("email", "username") and "@" in ident.value and \
                candidate.location in ("login", "forgot-password", "account-lookup",
                                       "registration", "account-update"):
            valid = ident.value
            break
    if valid is None and identifiers:
        valid = identifiers[0].value
    if valid is None:
        valid = extract_param_value(exchange, candidate) or "test@example.com"
    nonexistent = random_email("test") if "@" in valid else random_username("test")
    return valid, nonexistent


def _run_tests(args, exchanges) -> int:
    candidates = _load_candidates(args, exchanges)
    identifiers = _load_identifiers(args, exchanges)
    by_path = {e.path: e for e in exchanges}

    hosts = {e.host for e in exchanges}
    allowed = args.scope or list(hosts)

    if not args.dry_run and not args.confirm:
        print("Refusing to send live HTTP without --confirm. "
              "Re-run with --confirm (or use --dry-run).")
        return 2

    findings = []
    headers = _parse_headers(args.header)
    for cand in candidates:
        ex = by_path.get(cand.path)
        if ex is None:
            continue
        if not in_scope(ex.host, allowed):
            print(f"Skipping out-of-scope host {ex.host} (not in scope {allowed}).")
            return 3
        valid_value, nonexistent_value = _pick_value(cand, identifiers, ex)
        finding = test_candidate(ex, cand, valid_value, nonexistent_value,
                                 samples=args.samples, rate=args.rate,
                                 timeout=args.timeout, extra_headers=headers)
        findings.append(finding)

    print(render_console(findings))
    if args.output:
        write_json_report(findings, args.output)
        print(f"Wrote report to {args.output}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    exchanges = parse_session(args.xml)

    if args.command == "identify":
        candidates = identify_candidates(exchanges)
        data = [{"method": c.method, "path": c.path, "location": c.location,
                 "identifier_param": c.identifier_param,
                 "param_location": c.param_location, "reason": c.reason}
                for c in candidates]
        with open(args.out, "w") as fh:
            json.dump(data, fh, indent=2)
        for c in candidates:
            print(f"[{c.location}] {c.method} {c.path} param={c.identifier_param} "
                  f"— {c.reason}")
        print(f"Wrote {len(candidates)} candidates to {args.out}")
        return 0

    if args.command == "extract":
        identifiers = extract_identifiers(exchanges)
        data = [{"value": i.value, "type": i.type, "source": i.source}
                for i in identifiers]
        with open(args.out, "w") as fh:
            json.dump(data, fh, indent=2)
        for i in identifiers:
            print(f"{i.type}: {i.value}  (from {i.source})")
        print(f"Wrote {len(identifiers)} identifiers to {args.out}")
        return 0

    if args.command in ("test", "run"):
        return _run_tests(args, exchanges)

    return 1


if __name__ == "__main__":
    sys.exit(main())
