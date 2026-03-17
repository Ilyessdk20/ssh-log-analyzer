"""CLI entrypoint for SSH log analysis."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analyzer import build_global_stats, detect_suspicious_ips, summarize_by_ip, summarize_failures_by_hour
from parser import events_to_dataframe, parse_log_file
from report import generate_outputs


def build_argument_parser() -> argparse.ArgumentParser:
    """Build and return the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Analyze Linux SSH logs and export security-focused summaries.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to SSH log file (auth.log or secure).",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        required=True,
        help="Output directory for generated CSV/TXT/PNG files.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Minimum failed attempts from an IP to flag it as suspicious (default: 5).",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to use when parsing logs (default: current year).",
    )
    return parser


def main() -> int:
    """Main execution flow for the CLI."""
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.threshold < 1:
        print("[ERROR] --threshold must be >= 1")
        return 1

    try:
        events = parse_log_file(args.input, year=args.year)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        return 1
    except OSError as exc:
        print(f"[ERROR] Could not read input log file: {exc}")
        return 1

    if not events:
        print("[WARN] No matching SSH events found (Failed/Accepted password).")

    events_df = events_to_dataframe(events)
    ip_summary_df = summarize_by_ip(events_df)
    hourly_df = summarize_failures_by_hour(events_df)
    suspicious_df = detect_suspicious_ips(ip_summary_df, threshold=args.threshold)
    stats = build_global_stats(events_df)

    try:
        output_files = generate_outputs(
            events_df=events_df,
            ip_summary_df=ip_summary_df,
            hourly_df=hourly_df,
            suspicious_df=suspicious_df,
            outdir=args.outdir,
            threshold=args.threshold,
            stats=stats,
        )
    except OSError as exc:
        print(f"[ERROR] Could not write output files: {exc}")
        return 1

    print("[INFO] Analysis completed.")
    print(f"[INFO] Total parsed events: {stats['total_events']}")
    print(f"[INFO] Failed attempts: {stats['failed_events']}")
    print(f"[INFO] Successful logins: {stats['accepted_events']}")
    print(f"[INFO] Suspicious IPs (threshold={args.threshold}): {len(suspicious_df)}")

    print("[INFO] Generated files:")
    for name, path in output_files.items():
        print(f"  - {name}: {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
