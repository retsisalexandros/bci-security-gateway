from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_pps: float = 400.0, window: float = 1.0):
        self.max_pps = max_pps
        self.window = window
        self._packets: dict[str, deque] = defaultdict(deque)

    def allow(self, device_id: str) -> bool:
        now = time.monotonic()
        q = self._packets[device_id]
        q.append(now)
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return len(q) <= self.max_pps * self.window

    def reset(self, device_id: str) -> None:
        self._packets.pop(device_id, None)


class BehaviouralDetector:
    def __init__(
        self,
        learn_samples: int = 300,
        z_threshold: float = 6.0,
        channel_bound: float = 300.0,
    ):
        self.learn_samples = learn_samples
        self.z_threshold = z_threshold
        self.channel_bound = channel_bound
        self._state: dict[str, dict] = {}

    def observe(self, device_id: str, packet: dict) -> str | None:
        st = self._state.get(device_id)
        if st is None:
            st = {"packets": 0, "n": 0, "mean": 0.0, "m2": 0.0, "std": 1.0, "ready": False}
            self._state[device_id] = st

        channels = packet.get("channels") or []

        for v in channels:
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                if abs(v) > self.channel_bound:
                    return f"channel_out_of_bounds value={v}"

        if not st["ready"]:
            st["packets"] += 1
            for v in channels:
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    st["n"] += 1
                    d = v - st["mean"]
                    st["mean"] += d / st["n"]
                    st["m2"] += d * (v - st["mean"])
            if st["packets"] >= self.learn_samples and st["n"] > 1:
                st["std"] = (st["m2"] / st["n"]) ** 0.5 or 1.0
                st["ready"] = True
            return None

        for v in channels:
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                continue
            z = abs(v - st["mean"]) / st["std"]
            if z > self.z_threshold:
                return f"channel_anomaly z={z:.1f} value={v}"
        return None

    def reset(self, device_id: str) -> None:
        self._state.pop(device_id, None)
