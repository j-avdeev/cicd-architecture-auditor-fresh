from __future__ import annotations

import argparse
from pathlib import Path

from auditor.config import app_env, gitlab_connection_from_env
from auditor.discovery import discover_ci_files
from auditor.gitlab_api import fetch_gitlab_recent_runs
from auditor.report import write_reports
from auditor.rules import analyze


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CI/CD Architecture Auditor MVP")
    parser.add_argument("target", help="Repository or demo directory to analyze")
    parser.add_argument("--output-dir", default="out", help="Directory where reports will be written")
    parser.add_argument("--markdown-only", action="store_true", help="Skip HTML report generation")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    target = Path(args.target).resolve()
    output_dir = Path(args.output_dir).resolve()
    env_values = app_env(Path(__file__).resolve().parent.parent)
    gitlab_connection = gitlab_connection_from_env(env_values)

    if not target.exists():
        raise SystemExit(f"Target path does not exist: {target}")

    files = discover_ci_files(target)
    if not files:
        raise SystemExit(f"No supported CI files found under: {target}")

    recent_runs = None
    if gitlab_connection.enabled:
        try:
            recent_runs = fetch_gitlab_recent_runs(gitlab_connection)
        except Exception as exc:  # noqa: BLE001
            print(f"GitLab metadata fetch skipped: {exc}")

    result = analyze(target, files, recent_runs=recent_runs)
    outputs = write_reports(result, output_dir, html_enabled=not args.markdown_only)

    print(f"Analyzed {len(files)} CI files in {target}")
    print(f"Findings: {len(result.findings)}")
    print(f"Overall score: {result.overall_score}/100")
    for path in outputs:
        print(f"Wrote {path}")
    return 0
