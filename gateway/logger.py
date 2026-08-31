from __future__ import annotations

import json
import time
import asyncio
import logging
from collections import deque

logger = logging.getLogger(__name__)


class EventLogger:
    def __init__(self, log_path: str = "gateway_events.log"):
        self.log_path = log_path
        self._file = open(log_path, "a")
        self.event_queue: deque[dict] = deque(maxlen=1000)

    def log(self, event_type: str, device_id: str = "", details: str = "") -> dict:
        entry = {
            "timestamp": int(time.time() * 1000),
            "event_type": event_type,
            "device_id": device_id,
            "details": details,
        }
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()
        self.event_queue.append(entry)
        if event_type == "packet_forwarded":
            logger.debug("%s | %s | %s", event_type, device_id, details)
        else:
            logger.info("%s | %s | %s", event_type, device_id, details)
        return entry

    def close(self):
        self._file.close()
