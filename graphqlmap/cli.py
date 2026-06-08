"""Command-line interface for GRAPHQLMAP."""

from __future__ import annotations

import argparse
import html
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    AnalysisReport,
    Severity,
    analyze_introspection,
    load_introspection,
    DEFAULT_DEPTH_THRESHOLD,
)

_SEV_COLOR = {
    "CRITICAL": "#7b1fa2",
    "HIGH": "#c62828",
    "MEDIUM": "#ef6c00",
    "LOW": "#f9a825",
    "INFO": "#1565c0",
}


def _render_table(report: AnalysisReport) -> str:
    lines: List[str] = []
    s = report.stats
    lines.append(f"{TOOL_NAME} v{TOOL_VERSION} - GraphQL attack-surface analysis")
    lines.append("=" * 64)
    lines.append(f"Query type      : {s.get('query_type')}")
    lines.append(f"Mutation type   : {s.get('mutation_type')}")
    lines.append(f"Types           : {s.get('total_types')} ({s.get('user_types')} user-defined)")
    lines.append(f"Fields          : {s.get('total_fields')}")
    lines.append(f"Max query depth : {s.get('max_query_depth')}")
    lines.append("")
    counts = report.severity_counts()
    summary = "  ".join(f"{k}:{counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    lines.append(f"Findings ({len(report.findings)}):  {summary}")
    lines.append("-" * 64)
    if not report.findings:
        lines.append("No findings.")
    for f in report.findings:
        lines.append(f"[{f.severity.value:<8}] {f.id}  {f.title}")
        lines.append(f"             location : {f.location}")
        lines.append(f"             detail   : {f.detail}")
        lines.append(f"             fix      : {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


def _render_html(report: AnalysisReport) -> str:
    s = report.stats
    counts = report.severity_counts()
    rows = []
    for f in report.findings:
        color = _SEV_COLOR.get(f.severity.value, "#555")
        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>{html.escape(f.severity.value)}</span></td>"
            f"<td class='mono'>{html.escape(f.id)}</td>"
            f"<td>{html.escape(f.title)}<div class='detail'>{html.escape(f.detail)}</div>"
            f"<div class='fix'>Fix: {html.escape(f.recommendation)}</div></td>"
            f"<td class='mono'>{html.escape(f.location)}</td>"
            "</tr>"
        )
    if not report.findings:
        rows.append("<tr><td colspan='4'>No findings.</td></tr>")

    chips = "".join(
        f"<span class='chip' style='background:{_SEV_COLOR[k]}'>{k}: {counts[k]}</span>"
        for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    max_sev = report.max_severity.value if report.max_severity else "NONE"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
         margin: 0; background: #0f1115; color: #e6e6e6; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 28px 20px 60px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color: #9aa0a6; font-size: 13px; margin-bottom: 20px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 18px; }}
  .card {{ background: #1a1d24; border: 1px solid #2a2e37; border-radius: 10px;
          padding: 12px 16px; min-width: 130px; }}
  .card .k {{ font-size: 11px; text-transform: uppercase; color: #9aa0a6; letter-spacing: .5px; }}
  .card .v {{ font-size: 20px; font-weight: 600; margin-top: 4px; }}
  .chips {{ margin: 6px 0 22px; }}
  .chip, .badge {{ color: #fff; border-radius: 20px; padding: 3px 10px;
          font-size: 12px; font-weight: 600; margin-right: 6px; display: inline-block; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d24;
          border-radius: 10px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 12px 14px; vertical-align: top;
          border-bottom: 1px solid #2a2e37; font-size: 14px; }}
  th {{ background: #21252e; font-size: 12px; text-transform: uppercase; color: #9aa0a6; }}
  .detail {{ color: #b9bec6; font-size: 12.5px; margin-top: 5px; }}
  .fix {{ color: #7fd1a0; font-size: 12.5px; margin-top: 5px; }}
  .mono {{ font-family: ui-monospace, Consolas, monospace; font-size: 12.5px; }}
  .maxsev {{ font-weight: 700; }}
</style></head>
<body><div class="wrap">
  <h1>{TOOL_NAME} &mdash; GraphQL attack-surface report</h1>
  <div class="sub">{TOOL_NAME} v{TOOL_VERSION} &middot; highest severity:
     <span class="maxsev" style="color:{_SEV_COLOR.get(max_sev, '#fff')}">{max_sev}</span></div>
  <div class="cards">
    <div class="card"><div class="k">Query type</div><div class="v">{html.escape(str(s.get('query_type')))}</div></div>
    <div class="card"><div class="k">Mutation type</div><div class="v">{html.escape(str(s.get('mutation_type')))}</div></div>
    <div class="card"><div class="k">Types</div><div class="v">{s.get('total_types')}</div></div>
    <div class="card"><div class="k">Fields</div><div class="v">{s.get('total_fields')}</div></div>
    <div class="card"><div class="k">Max depth</div><div class="v">{s.get('max_query_depth')}</div></div>
    <div class="card"><div class="k">Findings</div><div class="v">{len(report.findings)}</div></div>
  </div>
  <div class="chips">{chips}</div>
  <table>
    <thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Location</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div></body></html>"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Analyze a GraphQL introspection result for risky fields, "
                    "excessive depth, and authorization gaps (defensive / authorized use only).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("analyze", help="Analyze an introspection JSON file.")
    a.add_argument("introspection", help="Path to introspection JSON (the __schema query result).")
    a.add_argument("--format", choices=("table", "json", "html"), default="table",
                   help="Output format. 'html' writes a self-contained report.")
    a.add_argument("-o", "--output", help="Write output to this file instead of stdout.")
    a.add_argument("--depth-threshold", type=int, default=DEFAULT_DEPTH_THRESHOLD,
                   help=f"Depth at which nesting is flagged (default {DEFAULT_DEPTH_THRESHOLD}).")
    a.add_argument("--fail-on", choices=("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
                   default="LOW", help="Minimum severity that triggers non-zero exit (default LOW).")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "analyze":
        parser.print_help()
        return 2

    try:
        schema = load_introspection(args.introspection)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    report = analyze_introspection(
        schema,
        depth_threshold=args.depth_threshold,
        tool=TOOL_NAME,
        version=TOOL_VERSION,
    )

    if args.format == "json":
        out = json.dumps(report.to_dict(), indent=2)
    elif args.format == "html":
        out = _render_html(report)
    else:
        out = _render_table(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
        except OSError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 2
        sys.stderr.write(f"wrote {args.format} report to {args.output}\n")
    else:
        sys.stdout.write(out + "\n")

    fail_on = Severity(args.fail_on)
    return 1 if report.has_findings(fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
