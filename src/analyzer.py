"""Analytical functions for parsed SSH events."""

from __future__ import annotations

from typing import Dict, Optional

import pandas as pd


def summarize_by_ip(events_df: pd.DataFrame) -> pd.DataFrame:
    """Build an IP-level summary with failed and successful login counters."""
    columns = ["ip", "failed_attempts", "successful_logins", "total_events"]
    if events_df.empty:
        return pd.DataFrame(columns=columns)

    failed = (
        events_df[events_df["event_type"] == "failed"]
        .groupby("ip")
        .size()
        .rename("failed_attempts")
    )
    success = (
        events_df[events_df["event_type"] == "accepted"]
        .groupby("ip")
        .size()
        .rename("successful_logins")
    )

    summary = pd.concat([failed, success], axis=1).fillna(0)
    summary = summary.astype(int)
    summary["total_events"] = summary["failed_attempts"] + summary["successful_logins"]

    summary = (
        summary.sort_values(["total_events", "failed_attempts"], ascending=False)
        .reset_index()
        .loc[:, columns]
    )
    return summary


def summarize_failures_by_hour(events_df: pd.DataFrame) -> pd.DataFrame:
    """Count failed SSH login attempts per hour."""
    columns = ["hour", "failed_attempts"]
    if events_df.empty:
        return pd.DataFrame(columns=columns)

    hourly = (
        events_df[events_df["event_type"] == "failed"]
        .groupby("hour")
        .size()
        .rename("failed_attempts")
        .reset_index()
    )

    if hourly.empty:
        return pd.DataFrame(columns=columns)

    hourly["hour"] = hourly["hour"].astype(str).str.zfill(2)
    hourly = hourly.sort_values("hour").reset_index(drop=True)
    return hourly


def detect_suspicious_ips(ip_summary_df: pd.DataFrame, threshold: int) -> pd.DataFrame:
    """Filter suspicious IPs where failed attempts meet or exceed a threshold."""
    columns = ["ip", "failed_attempts", "successful_logins", "total_events"]
    if ip_summary_df.empty:
        return pd.DataFrame(columns=columns)

    suspicious = ip_summary_df[ip_summary_df["failed_attempts"] >= threshold].copy()
    suspicious = suspicious.sort_values("failed_attempts", ascending=False).reset_index(drop=True)
    return suspicious.loc[:, columns]


def build_global_stats(events_df: pd.DataFrame) -> Dict[str, Optional[int]]:
    """Compute high-level metrics used in the final text report."""
    if events_df.empty:
        return {
            "total_events": 0,
            "failed_events": 0,
            "accepted_events": 0,
            "unique_ips": 0,
            "busiest_failure_hour": None,
            "busiest_failure_count": None,
        }

    failed_events = int((events_df["event_type"] == "failed").sum())
    accepted_events = int((events_df["event_type"] == "accepted").sum())
    busiest_failure_hour = None
    busiest_failure_count = None

    if failed_events > 0:
        hourly_failures = (
            events_df[events_df["event_type"] == "failed"]
            .groupby("hour")
            .size()
            .sort_values(ascending=False)
        )
        busiest_failure_hour = str(hourly_failures.index[0]).zfill(2)
        busiest_failure_count = int(hourly_failures.iloc[0])

    return {
        "total_events": int(len(events_df)),
        "failed_events": failed_events,
        "accepted_events": accepted_events,
        "unique_ips": int(events_df["ip"].nunique()),
        "busiest_failure_hour": busiest_failure_hour,
        "busiest_failure_count": busiest_failure_count,
    }
