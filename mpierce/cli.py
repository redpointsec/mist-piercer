# mpierce/cli.py
import argparse
import json
import sys

from .burp import parse_session
from .identify import identify_candidates
from .extract import extract_identifiers
from .generate import random_email, random_numeric, random_username
from .http_tester import in_scope, extract_param_value, test_candidate
from .models import Candidate, Identifier
from .report import write_json_report, render_console


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
        p.add_argument("--samples", type=int, default=1,
                       help="samples per value (raise to 5+ to enable the timing signal)")
        p.add_argument("--rate", type=float, default=3.0)
        p.add_argument("--timeout", type=float, default=10.0)
        p.add_argument("--max-values", type=int, default=25,
                       help="max known values to test per candidate")
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
        else:
            print(f"Ignoring malformed --header (expected 'Name: Value'): {h!r}")
    return headers


def _load_candidates(args, exchanges) -> list[Candidate]:
    if getattr(args, "candidates", None):
        with open(args.candidates) as fh:
            data = json.load(fh)
        out = []
        for c in data:
            ex = _resolve_exchange(exchanges, c["method"], c["path"])
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


def _resolve_exchange(exchanges, method, path):
    """Pick the captured exchange to replay for a candidate: match on
    (method, path), preferring one that carries a request body so form/json
    substitution has something to replace. (A path can appear multiple times
    — e.g. the GET form page and the POST submission — so keying on path
    alone would pick the wrong one.)"""
    matches = [e for e in exchanges if e.method == method and e.path == path]
    if not matches:
        return None
    for e in matches:
        if e.request_body:
            return e
    return matches[0]


def _nonexistent_like(valid: str) -> str:
    """A guaranteed-nonexistent value shaped like `valid` so existence is the
    only variable (not format)."""
    if "@" in valid:
        return random_email("test")
    if valid.isdigit():
        return random_numeric(len(valid))
    return random_username("test")


def _pick_values(candidate: Candidate, identifiers: list[Identifier],
                 exchange) -> tuple[list[str], str]:
    """Return (known_values, nonexistent_baseline) for a candidate.

    Known values are scoped to THIS endpoint: identifiers harvested from the
    candidate's own path are used first. Only if none match do we fall back to
    shape-compatible identifiers. The captured param value is always included.
    Scoping is what keeps a run small and on-target — without it every endpoint
    would be tested against every identifier."""
    captured = extract_param_value(exchange, candidate)
    shape = captured or (identifiers[0].value if identifiers else "test@example.com")

    def fits(v: str) -> bool:
        if "@" in shape:
            return "@" in v
        if shape.isdigit():
            return v.isdigit()
        return "@" not in v and not v.isdigit()   # username-like

    # 1. identifiers captured from this exact endpoint
    known = [i.value for i in identifiers if i.source == candidate.path]
    # 2. fall back to shape-compatible identifiers only if the endpoint had none
    if not known:
        known = [i.value for i in identifiers if fits(i.value)]
    if captured:
        known.append(captured)
    known = list(dict.fromkeys(known))   # dedup, preserve order
    if not known:
        known = [shape]
    return known, _nonexistent_like(known[0])


def _run_tests(args, exchanges) -> int:
    try:
        candidates = _load_candidates(args, exchanges)
        identifiers = _load_identifiers(args, exchanges)
    except json.JSONDecodeError as exc:
        print(f"Could not parse JSON input: {exc}")
        return 4
    hosts = {e.host for e in exchanges}
    allowed = args.scope or list(hosts)

    if not args.dry_run and not args.confirm:
        print("Refusing to send live HTTP without --confirm. "
              "Re-run with --confirm (or use --dry-run).")
        return 2

    findings = []
    skipped = 0
    headers = _parse_headers(args.header)
    print(f"[*] {len(candidates)} candidate(s) to test "
          f"({'DRY RUN — no traffic' if args.dry_run else f'live, {args.rate}/s'})",
          file=sys.stderr)
    for cand in candidates:
        ex = _resolve_exchange(exchanges, cand.method, cand.path)
        if ex is None:
            print(f"[!] skip {cand.method} {cand.path}: no captured request matches",
                  file=sys.stderr)
            continue
        if not in_scope(ex.host, allowed):
            print(f"[!] skip out-of-scope host {ex.host} (allowed: {allowed})",
                  file=sys.stderr)
            skipped += 1
            continue
        known_values, nonexistent_value = _pick_values(cand, identifiers, ex)
        if len(known_values) > args.max_values:
            print(f"[*] {cand.path}: capping {len(known_values)} values to "
                  f"{args.max_values} (raise with --max-values)", file=sys.stderr)
            known_values = known_values[:args.max_values]
        print(f"[*] {cand.method} {cand.path} ({cand.location}): "
              f"{len(known_values)} value(s) + baseline, "
              f"{(len(known_values) + 1) * args.samples} request(s)", file=sys.stderr)
        finding = test_candidate(ex, cand, known_values, nonexistent_value,
                                 samples=args.samples, rate=args.rate,
                                 timeout=args.timeout, extra_headers=headers,
                                 dry_run=args.dry_run)
        hits = sum(1 for r in finding.results if r.enumerable)
        print(f"    -> {hits} enumerable value(s)", file=sys.stderr)
        findings.append(finding)

    if not findings and not skipped:
        print("[!] No candidates resolved to captured requests — nothing tested.",
              file=sys.stderr)
    print(render_console(findings))
    if args.output:
        write_json_report(findings, args.output)
        print(f"Wrote report to {args.output}")
    if not findings and skipped:
        print("No in-scope candidates were tested.")
        return 3
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    exchanges = parse_session(args.xml)

    if args.command == "identify":
        try:
            candidates = identify_candidates(exchanges)
        except json.JSONDecodeError as exc:
            print(f"LLM did not return valid JSON for identify: {exc}")
            return 4
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
        try:
            identifiers = extract_identifiers(exchanges)
        except json.JSONDecodeError as exc:
            print(f"LLM did not return valid JSON for extract: {exc}")
            return 4
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
