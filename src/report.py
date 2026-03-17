"""Output generation: CSV exports, text report, and charts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import pandas as pd


def ensure_output_dir(outdir: Path) -> None:
    """Create output directory if needed."""
    outdir.mkdir(parents=True, exist_ok=True)


def _save_dataframe(df: pd.DataFrame, output_file: Path) -> None:
    """Save a DataFrame to CSV with consistent settings."""
    df.to_csv(output_file, index=False)


def _save_failed_by_hour_plot(hourly_df: pd.DataFrame, output_file: Path) -> None:
    """Create a PNG bar chart for failed attempts grouped by hour."""
    plt.figure(figsize=(10, 5))

    if hourly_df.empty:
        plt.text(
            0.5,
            0.5,
            "No failed login attempts found.",
            ha="center",
            va="center",
            fontsize=11,
        )
        plt.xlim(0, 1)
        plt.ylim(0, 1)
    else:
        bars = plt.bar(hourly_df["hour"], hourly_df["failed_attempts"], color="#c0392b")
        for bar in bars:
            height = bar.get_height()
            plt.text(
                bar.get_x() + bar.get_width() / 2,
                height + 0.05,
                str(int(height)),
                ha="center",
                va="bottom",
                fontsize=9,
            )

    plt.title("Failed SSH Login Attempts by Hour")
    plt.xlabel("Hour")
    plt.ylabel("Number of failed attempts")
    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()


def _build_text_report(
    stats: Dict[str, int],
    threshold: int,
    ip_summary_df: pd.DataFrame,
    suspicious_df: pd.DataFrame,
) -> str:
    """Create a human-readable report text from analysis outputs."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "SSH Log Analyzer Report",
        "=======================",
        f"Generated at: {now_str}",
        "",
        "Global statistics",
        "-----------------",
        f"Total parsed events: {stats['total_events']}",
        f"Failed login attempts: {stats['failed_events']}",
        f"Successful logins: {stats['accepted_events']}",
        f"Unique source IPs: {stats['unique_ips']}",
    ]

    if stats["busiest_failure_hour"] is not None:
        lines.append(
            f"Busiest failure hour: {stats['busiest_failure_hour']}:00 "
            f"({stats['busiest_failure_count']} failed attempts)"
        )
    else:
        lines.append("Busiest failure hour: N/A")

    lines.extend(["", "Top active IPs", "--------------"])
    if ip_summary_df.empty:
        lines.append("No IP activity found.")
    else:
        top_rows = ip_summary_df.head(5)
        for _, row in top_rows.iterrows():
            lines.append(
                f"- {row['ip']}: total={int(row['total_events'])}, "
                f"failed={int(row['failed_attempts'])}, "
                f"accepted={int(row['successful_logins'])}"
            )

    lines.extend(["", f"Suspicious IPs (threshold >= {threshold} failed attempts)", "----------------------------------------------"])
    if suspicious_df.empty:
        lines.append("No suspicious IP detected.")
    else:
        for _, row in suspicious_df.iterrows():
            lines.append(
                f"- {row['ip']} ({int(row['failed_attempts'])} failed attempts, "
                f"total events={int(row['total_events'])})"
            )

    return "\n".join(lines) + "\n"


def generate_outputs(
    events_df: pd.DataFrame,
    ip_summary_df: pd.DataFrame,
    hourly_df: pd.DataFrame,
    suspicious_df: pd.DataFrame,
    outdir: Path,
    threshold: int,
    stats: Dict[str, int],
) -> Dict[str, Path]:
    """Generate all expected project artifacts into output directory."""
    ensure_output_dir(outdir)

    output_files = {
        "parsed_events_csv": outdir / "parsed_events.csv",
        "ip_summary_csv": outdir / "ip_summary.csv",
        "hourly_failures_csv": outdir / "hourly_failures.csv",
        "suspicious_ips_csv": outdir / "suspicious_ips.csv",
        "report_txt": outdir / "report.txt",
        "failed_by_hour_png": outdir / "failed_by_hour.png",
    }

    _save_dataframe(events_df, output_files["parsed_events_csv"])
    _save_dataframe(ip_summary_df, output_files["ip_summary_csv"])
    _save_dataframe(hourly_df, output_files["hourly_failures_csv"])
    _save_dataframe(suspicious_df, output_files["suspicious_ips_csv"])

    report_text = _build_text_report(
        stats=stats,
        threshold=threshold,
        ip_summary_df=ip_summary_df,
        suspicious_df=suspicious_df,
    )
    output_files["report_txt"].write_text(report_text, encoding="utf-8")

    _save_failed_by_hour_plot(hourly_df, output_files["failed_by_hour_png"])

    return output_files
