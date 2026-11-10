"""One-off: run the TrustLens URL pipeline against a target and print the report.

Passive checks only (no JS execution, no downloads, SSRF-guarded).
"""
import asyncio
import json
import sys

sys.path.insert(0, ".")

from app.config import get_settings
from app.pipeline.runner import analyze_url


async def main() -> None:
    target = sys.argv[1]
    report = await analyze_url(target, get_settings(), persist=False)
    print("== TrustLens report ==")
    print("target:          ", report.normalized.url if report.normalized else target)
    print("registrable:     ", report.normalized.registrable_domain if report.normalized else None)
    print("classification:  ", report.classification.value)
    print("rationale:       ", report.classification_rationale[:200])
    print("coverage:        ", f"{report.coverage.completed}/{report.coverage.attempted}",
          "| unavailable:", report.coverage.unavailable_checks)
    print("findings:")
    for f in report.findings:
        print(f"  - [{f.severity.value:>6}] {f.id}: {f.title}")
        for e in f.evidence[:2]:
            print(f"        {e[:150]}")
    if report.fetch:
        print("fetch:           ", f"status={report.fetch.status_code} ok={report.fetch.ok} "
                                   f"error_kind={report.fetch.error_kind.value}")
        if report.fetch.title:
            print("page title:      ", report.fetch.title[:100])
    print("report_id:       ", report.report_id)
    print("sha256:          ", report.integrity.canonical_json_sha256 if report.integrity else None)


asyncio.run(main())
