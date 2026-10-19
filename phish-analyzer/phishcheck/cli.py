"""Command-line interface: python -m phishcheck message.eml"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from .analyzer import Report, analyze_file
from .enrich import enrich_report

EXIT_CODES = {"low risk": 0, "suspicious": 1, "likely phishing": 2}


def format_report(report: Report) -> str:
    lines = [
        f"Subject:   {report.subject or '(none)'}",
        f"From:      {report.sender or '(none)'}",
        f"Origin IP: {report.origin_ip or 'unknown'}",
        f"Verdict:   {report.verdict.upper()} (score {report.score}/100)",
        "",
    ]
    if report.findings:
        lines.append("Findings:")
        for finding in report.findings:
            lines.append(f"  [+{finding.points:>2}] {finding.message}")
            lines.extend(f"         {evidence}" for evidence in finding.evidence)
    else:
        lines.append("No findings.")

    if report.urls:
        lines += ["", f"Links ({len(report.urls)}):"]
        for url in report.urls:
            lines.append(f"  {url}")
            if url in report.enrichment:
                result = report.enrichment[url]
                if result is None:
                    lines.append("     VirusTotal: lookup failed")
                elif result.get("status") == "unknown":
                    lines.append("     VirusTotal: never seen")
                else:
                    lines.append(
                        f"     VirusTotal: {result['malicious']} malicious, "
                        f"{result['suspicious']} suspicious"
                    )
    if report.attachments:
        lines += ["", f"Attachments ({len(report.attachments)}):"]
        for att in report.attachments:
            lines.append(f"  {att.filename}  {att.content_type}  {att.size} B")
            lines.append(f"     sha256 {att.sha256}")

    lines += ["", "Heuristic result: a low score does not guarantee the message is safe."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phishcheck", description="Heuristic phishing analysis of a .eml file."
    )
    parser.add_argument("eml", help="path to a .eml file")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="look up links on VirusTotal (needs VT_API_KEY; sends the URLs to VirusTotal)",
    )
    parser.add_argument("--max-lookups", type=int, default=4, help="max links to look up (default 4)")
    args = parser.parse_args(argv)

    try:
        report = analyze_file(args.eml)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.enrich:
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            print("error: --enrich needs the VT_API_KEY environment variable", file=sys.stderr)
            return 3
        enrich_report(report, api_key, max_lookups=args.max_lookups)

    print(json.dumps(asdict(report), indent=2) if args.json else format_report(report))
    return EXIT_CODES[report.verdict]
