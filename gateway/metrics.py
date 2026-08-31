from __future__ import annotations

import time
from collections import deque


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    k = (len(ordered) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo), 4)


class Metrics:
    def __init__(self):
        self.total_packets_received = 0
        self.total_packets_forwarded = 0
        self.total_packets_rejected = 0
        self.auth_failures = 0
        self.replay_rejections = 0
        self.malformed_packets = 0
        self.rate_limited = 0
        self.anomalies_detected = 0
        self._start_time = time.time()
        self._latency_sum = 0.0
        self._latency_count = 0
        self._latencies: deque[float] = deque(maxlen=1000)

    def record_received(self):
        self.total_packets_received += 1

    def record_forwarded(self, latency_ms: float = 0.0):
        self.total_packets_forwarded += 1
        self._latency_sum += latency_ms
        self._latency_count += 1
        self._latencies.append(latency_ms)

    def record_rejected(self, reason: str):
        self.total_packets_rejected += 1
        if reason in ("stale_timestamp", "duplicate_seq"):
            self.replay_rejections += 1
        elif reason in ("malformed_packet", "invalid_json"):
            self.malformed_packets += 1
        elif reason == "rate_limited":
            self.rate_limited += 1

    def record_auth_failure(self):
        self.auth_failures += 1

    def record_anomaly(self):
        self.anomalies_detected += 1

    def snapshot(self) -> dict:
        elapsed = max(time.time() - self._start_time, 1)
        samples = list(self._latencies)
        return {
            "total_packets_received": self.total_packets_received,
            "total_packets_forwarded": self.total_packets_forwarded,
            "total_packets_rejected": self.total_packets_rejected,
            "auth_failures": self.auth_failures,
            "replay_rejections": self.replay_rejections,
            "malformed_packets": self.malformed_packets,
            "rate_limited": self.rate_limited,
            "anomalies_detected": self.anomalies_detected,
            "packets_per_second": round(self.total_packets_received / elapsed, 1),
            "avg_latency_ms": round(
                self._latency_sum / self._latency_count
                if self._latency_count > 0
                else 0,
                4,
            ),
            "latency_p50_ms": _percentile(samples, 50),
            "latency_p95_ms": _percentile(samples, 95),
            "latency_p99_ms": _percentile(samples, 99),
        }
