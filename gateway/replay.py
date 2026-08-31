from __future__ import annotations

import time
import logging

logger = logging.getLogger(__name__)


class ReplayDetector:
    def __init__(self, time_window: float = 5.0):
        self.time_window = time_window
        self._last_seq: dict[str, int] = {}

    def validate(self, device_id: str, seq: int, timestamp_ms: int) -> str | None:
        now_ms = int(time.time() * 1000)
        drift = abs(now_ms - timestamp_ms) / 1000.0
        if drift > self.time_window:
            logger.warning(
                "Stale timestamp from %s: drift=%.1fs, seq=%d",
                device_id, drift, seq,
            )
            return "stale_timestamp"

        last = self._last_seq.get(device_id, -1)
        if seq <= last:
            logger.warning(
                "Duplicate/old seq from %s: got=%d, last=%d",
                device_id, seq, last,
            )
            return "duplicate_seq"

        self._last_seq[device_id] = seq
        return None

    def reset(self, device_id: str) -> None:
        self._last_seq.pop(device_id, None)
