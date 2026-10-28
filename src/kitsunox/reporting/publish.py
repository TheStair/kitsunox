"""Write a run's report: `report/report.json` (canonical) and the Markdown rendered from it."""

from __future__ import annotations

from pathlib import Path

from kitsunox.reporting.markdown import write_markdown
from kitsunox.reporting.report import REPORT_DIR, Report, build_report, write_report


def publish_report(run_dir: Path) -> Report:
    """From `correlate.jsonl`; the caller holds the data-dir lock."""
    report = build_report(run_dir)
    write_report(run_dir, report)
    write_markdown(run_dir / REPORT_DIR, report)
    return report
