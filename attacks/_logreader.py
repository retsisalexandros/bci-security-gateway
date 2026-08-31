from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable


def read_gateway_events(log_path: str | Path) -> list[dict]:
    p = Path(log_path)
    if not p.exists():
        return []
    events: list[dict] = []
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def events_in_window(
    events: Iterable[dict],
    since_ms: int,
    until_ms: int | None = None,
) -> list[dict]:
    if until_ms is None:
        until_ms = int(time.time() * 1000) + 1000
    return [
        e for e in events
        if isinstance(e.get("timestamp"), (int, float))
        and since_ms <= e["timestamp"] <= until_ms
    ]


def count_events(
    events: Iterable[dict],
    event_type: str,
    details_substr: str | None = None,
    device_id: str | None = None,
) -> int:
    n = 0
    for e in events:
        if e.get("event_type") != event_type:
            continue
        if details_substr is not None and details_substr not in str(e.get("details", "")):
            continue
        if device_id is not None and e.get("device_id") != device_id:
            continue
        n += 1
    return n


def count_hub_log_phrase(log_path: str | Path, phrase: str) -> int:
    p = Path(log_path)
    if not p.exists():
        return 0
    n = 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if phrase in line:
                n += 1
    return n


def read_hub_log_phrase_lines(log_path: str | Path, phrase: str) -> list[str]:
    p = Path(log_path)
    if not p.exists():
        return []
    out = []
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if phrase in line:
                out.append(line.rstrip("\n"))
    return out


def file_offset(log_path: str | Path) -> int:
    p = Path(log_path)
    if not p.exists():
        return 0
    return p.stat().st_size


def read_after_offset(log_path: str | Path, offset: int) -> str:
    p = Path(log_path)
    if not p.exists():
        return ""
    with p.open("rb") as f:
        f.seek(offset)
        return f.read().decode("utf-8", errors="replace")
