from __future__ import annotations

import json
import time
import asyncio
import logging

import websockets

from .auth import extract_device_id, check_allowlist
from .integrity import attach_hmac
from .replay import ReplayDetector
from .anomaly import RateLimiter, BehaviouralDetector
from .logger import EventLogger
from .metrics import Metrics

logger = logging.getLogger(__name__)

MAX_CHANNELS = 32


def check_packet_shape(packet) -> str | None:
    if not isinstance(packet, dict):
        return "not_an_object"
    seq = packet.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int):
        return "seq_not_int"
    if seq < 0:
        return "seq_negative"
    ts = packet.get("timestamp")
    if isinstance(ts, bool) or not isinstance(ts, int):
        return "timestamp_not_int"
    channels = packet.get("channels")
    if not isinstance(channels, list):
        return "channels_not_list"
    if len(channels) > MAX_CHANNELS:
        return "channels_too_long"
    return None


class GatewayProxy:
    def __init__(
        self,
        allowlist: list[str],
        hmac_key: str,
        time_window: float,
        event_logger: EventLogger,
        max_pps: float = 400.0,
        anomaly_learn_samples: int = 300,
        anomaly_z: float = 6.0,
        channel_bound: float = 300.0,
    ):
        self.allowlist = allowlist
        self.hmac_key = hmac_key
        self.replay = ReplayDetector(time_window=time_window)
        self.rate_limiter = RateLimiter(max_pps=max_pps)
        self.anomaly = BehaviouralDetector(
            learn_samples=anomaly_learn_samples,
            z_threshold=anomaly_z,
            channel_bound=channel_bound,
        )
        self.event_logger = event_logger
        self.metrics = Metrics()
        self.hub_clients: set = set()

    async def handle_device(self, ws):
        ssl_object = ws.transport.get_extra_info("ssl_object")
        if ssl_object is None:
            self.event_logger.log("auth_failure", details="No TLS")
            self.metrics.record_auth_failure()
            await ws.close(1008, "TLS required")
            return

        device_id = extract_device_id(ssl_object)
        if device_id is None:
            self.event_logger.log("auth_failure", details="No CN in cert")
            self.metrics.record_auth_failure()
            await ws.close(1008, "Invalid certificate")
            return

        if not check_allowlist(device_id, self.allowlist):
            self.event_logger.log(
                "auth_failure", device_id=device_id, details="Not in allowlist"
            )
            self.metrics.record_auth_failure()
            await ws.close(1008, "Device not allowed")
            return

        self.event_logger.log("auth_success", device_id=device_id)
        self.replay.reset(device_id)
        self.rate_limiter.reset(device_id)
        self.anomaly.reset(device_id)

        logger.info("Device %s authenticated and connected.", device_id)

        try:
            async for message in ws:
                await self._process_packet(message, device_id)
        except websockets.ConnectionClosed:
            logger.info("Device %s disconnected.", device_id)

    async def _process_packet(self, raw: str, device_id: str):
        start = time.perf_counter()
        self.metrics.record_received()

        if not self.rate_limiter.allow(device_id):
            self.event_logger.log(
                "rate_limited", device_id=device_id, details="packet rate exceeded"
            )
            self.metrics.record_rejected("rate_limited")
            return

        try:
            packet = json.loads(raw)
        except json.JSONDecodeError:
            self.event_logger.log(
                "packet_rejected", device_id=device_id, details="invalid_json"
            )
            self.metrics.record_rejected("invalid_json")
            return

        malformed = check_packet_shape(packet)
        if malformed:
            self.event_logger.log(
                "packet_rejected",
                device_id=device_id,
                details=f"malformed_packet {malformed}",
            )
            self.metrics.record_rejected("malformed_packet")
            return

        if packet.get("device_id") != device_id:
            self.event_logger.log(
                "packet_rejected",
                device_id=device_id,
                details=f"device_id_mismatch claimed={packet.get('device_id')}",
            )
            self.metrics.record_rejected("device_id_mismatch")
            return

        anomaly = self.anomaly.observe(device_id, packet)
        if anomaly:
            self.event_logger.log(
                "anomaly_detected", device_id=device_id, details=anomaly
            )
            self.metrics.record_anomaly()

        rejection = self.replay.validate(
            device_id, packet.get("seq", -1), packet.get("timestamp", 0)
        )
        if rejection:
            self.event_logger.log(
                "replay_rejected",
                device_id=device_id,
                details=f"{rejection} seq={packet.get('seq')} ts={packet.get('timestamp')}",
            )
            self.metrics.record_rejected(rejection)
            return

        secured_json = attach_hmac(packet, self.hmac_key)
        self.event_logger.log("packet_forwarded", device_id=device_id)

        latency_ms = (time.perf_counter() - start) * 1000
        self.metrics.record_forwarded(latency_ms)

        await self._broadcast_to_hub(secured_json)

    async def _broadcast_to_hub(self, message: str):
        if not self.hub_clients:
            return
        await asyncio.gather(
            *(c.send(message) for c in self.hub_clients.copy()),
            return_exceptions=True,
        )

    async def broadcast_event(self, event: dict):
        msg = json.dumps(event)
        await self._broadcast_to_hub(msg)

    async def broadcast_metrics(self):
        msg = json.dumps(self.metrics.snapshot())
        await self._broadcast_to_hub(msg)

    async def handle_hub(self, ws):
        self.hub_clients.add(ws)
        logger.info("Hub client connected (%d total).", len(self.hub_clients))
        try:
            async for _ in ws:
                pass
        except websockets.ConnectionClosed:
            pass
        finally:
            self.hub_clients.discard(ws)
            logger.info("Hub client disconnected (%d total).", len(self.hub_clients))
