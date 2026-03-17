"""Parsing utilities for SSH authentication logs."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

SSH_LOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<message>.+)$"
)

FAILED_RE = re.compile(
    r"^Failed password for(?: invalid user)? (?P<user>\S+) from "
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port (?P<port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from "
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port (?P<port>\d+)"
)


def parse_log_line(line: str, year: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Parse one SSH log line and return a structured event dict if relevant."""
    clean_line = line.strip()
    if not clean_line:
        return None

    base_match = SSH_LOG_RE.match(clean_line)
    if not base_match:
        return None

    message = base_match.group("message")
    event_type = None
    event_match = FAILED_RE.match(message)

    if event_match:
        event_type = "failed"
    else:
        event_match = ACCEPTED_RE.match(message)
        if event_match:
            event_type = "accepted"

    if not event_match or not event_type:
        return None

    parse_year = year if year is not None else datetime.now().year
    timestamp_str = (
        f"{parse_year} {base_match.group('month')} {base_match.group('day')} "
        f"{base_match.group('time')}"
    )

    try:
        timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "date": timestamp.date().isoformat(),
        "hour": timestamp.strftime("%H"),
        "user": event_match.group("user"),
        "ip": event_match.group("ip"),
        "port": int(event_match.group("port")),
        "event_type": event_type,
        "raw_line": clean_line,
    }


def parse_log_file(log_path: Path, year: Optional[int] = None) -> List[Dict[str, Any]]:
    """Read a log file and parse only SSH failed/accepted password events."""
    if not log_path.exists():
        raise FileNotFoundError(f"Input log file not found: {log_path}")

    events: List[Dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parsed_event = parse_log_line(line, year=year)
            if parsed_event is not None:
                events.append(parsed_event)

    return events


def events_to_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert parsed events into a normalized pandas DataFrame."""
    columns = ["timestamp", "date", "hour", "user", "ip", "port", "event_type", "raw_line"]

    if not events:
        return pd.DataFrame(columns=columns)

    frame = pd.DataFrame(events)
    frame = frame[columns].sort_values("timestamp").reset_index(drop=True)
    return frame
