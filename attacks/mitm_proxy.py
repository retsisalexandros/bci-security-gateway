"""ATK3 helper: on-path WebSocket MitM relay between gateway and a sidecar hub."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import signal
import sys
from typing import Optional

import websockets

logger = logging.getLogger("mitm_proxy")

TAMPERED_COMMANDS = ["confirm", "select_B", "move_right", "select_A"]


class MitmRelay:
    def __init__(self, mutation_rate: float, target_field: str = "command",
                 mutate_flag_file: Optional[str] = None):
        self.mutation_rate = mutation_rate
        self.target_field = target_field
        self.mutate_flag_file = mutate_flag_file
        self.hub_client: Optional[websockets.WebSocketServerProtocol] = None
        self.counters = {
            "forwarded_total": 0,
            "data_packets_seen": 0,
            "mutated": 0,
            "untouched": 0,
            "non_data_forwarded": 0,
            "relay_errors": 0,
        }

    async def hub_handler(self, ws):
        if self.hub_client is not None:
            logger.warning("Second hub client tried to connect; rejecting.")
            await ws.close(1008, "single client only")
            return
        self.hub_client = ws
        logger.info("Sidecar hub connected.")
        try:
            async for _ in ws:
                pass
        except websockets.ConnectionClosed:
            pass
        finally:
            self.hub_client = None
            logger.info("Sidecar hub disconnected.")

    def _maybe_mutate(self, raw: str) -> str:
        try:
            packet = json.loads(raw)
        except json.JSONDecodeError:
            return raw

        if "channels" not in packet:
            self.counters["non_data_forwarded"] += 1
            return raw

        self.counters["data_packets_seen"] += 1
        active = self.mutate_flag_file is None or os.path.exists(self.mutate_flag_file)
        if active and random.random() < self.mutation_rate:
            current = packet.get(self.target_field, "")
            choices = [c for c in TAMPERED_COMMANDS if c != current]
            if not choices:
                choices = TAMPERED_COMMANDS
            packet[self.target_field] = random.choice(choices)
            self.counters["mutated"] += 1
            return json.dumps(packet)
        else:
            self.counters["untouched"] += 1
            return raw

    async def gateway_consumer(self, gateway_uri: str):
        backoff = 1.0
        while True:
            try:
                logger.info("Connecting to gateway at %s ...", gateway_uri)
                async with websockets.connect(gateway_uri) as gw:
                    logger.info("Connected to gateway.")
                    backoff = 1.0
                    async for message in gw:
                        out = self._maybe_mutate(message)
                        if self.hub_client is None:
                            continue
                        try:
                            await self.hub_client.send(out)
                            self.counters["forwarded_total"] += 1
                        except websockets.ConnectionClosed:
                            logger.warning("Sidecar hub closed mid-forward.")
                            self.counters["relay_errors"] += 1
            except (OSError, websockets.ConnectionClosed, websockets.InvalidHandshake) as e:
                logger.warning("Gateway link error (%s), retrying in %.1fs.", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 5.0)


async def run_proxy(
    listen_host: str, listen_port: int, gateway_uri: str,
    mutation_rate: float, duration: float | None = None,
    mutate_flag_file: str | None = None,
):
    relay = MitmRelay(mutation_rate=mutation_rate, mutate_flag_file=mutate_flag_file)

    server = await websockets.serve(relay.hub_handler, listen_host, listen_port)
    logger.info("MitM relay listening on ws://%s:%d (mutation_rate=%.2f)",
                listen_host, listen_port, mutation_rate)

    consumer_task = asyncio.ensure_future(relay.gateway_consumer(gateway_uri))

    async def _emit_loop():
        while True:
            await asyncio.sleep(1.0)
            print(json.dumps({"mitm_counters": relay.counters}), flush=True)

    emit_task = (
        asyncio.ensure_future(_emit_loop()) if mutate_flag_file is None else None
    )

    stop_event = asyncio.Event()

    def _on_signal():
        logger.info("Shutdown signal received.")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except (NotImplementedError, RuntimeError):
            pass

    if duration:
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=duration)
        except asyncio.TimeoutError:
            logger.info("Run duration elapsed.")
    else:
        await stop_event.wait()

    consumer_task.cancel()
    if emit_task is not None:
        emit_task.cancel()
    server.close()
    await server.wait_closed()

    print(json.dumps({"mitm_counters": relay.counters}), flush=True)


def main():
    parser = argparse.ArgumentParser(description="On-path WebSocket MitM relay (ATK3)")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9101)
    parser.add_argument("--gateway-host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=9001)
    parser.add_argument(
        "--mutation-rate", type=float, default=1.0,
        help="Probability of mutating each data packet's command field "
             "(0.0=passive eavesdrop, 1.0=tamper everything)",
    )
    parser.add_argument(
        "--duration", type=float, default=None,
        help="Run for this many seconds then exit cleanly. If omitted, runs "
             "until interrupted.",
    )
    parser.add_argument(
        "--mutate-flag-file", default=None,
        help="If set, only mutate while this file exists (passthrough otherwise). "
             "Lets a demo toggle tampering on the live link.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    gateway_uri = f"ws://{args.gateway_host}:{args.gateway_port}"
    asyncio.run(run_proxy(
        args.listen_host, args.listen_port, gateway_uri,
        args.mutation_rate, args.duration, args.mutate_flag_file,
    ))


if __name__ == "__main__":
    main()
