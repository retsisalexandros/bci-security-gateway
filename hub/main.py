from __future__ import annotations
import argparse
import asyncio
import json
import logging
import time

import websockets

from .verifier import verify_and_strip
from .forwarder import dashboard_handler, broadcast

logger = logging.getLogger(__name__)


async def emit_integrity_violation(device_id: str):
    event = {
        "timestamp": int(time.time() * 1000),
        "event_type": "integrity_violation",
        "device_id": device_id,
        "details": "HMAC mismatch",
    }
    await broadcast(json.dumps(event))


async def baseline_upstream_handler(ws, mode: str, hmac_key: str | None):
    logger.info("Upstream connection established (mode=%s).", mode)
    try:
        async for message in ws:
            if mode == "secured" and hmac_key:
                clean = verify_and_strip(message, hmac_key)
                if clean is None:
                    continue
                await broadcast(clean)
            else:
                await broadcast(message)
    except websockets.ConnectionClosed:
        logger.info("Upstream connection closed.")


async def secured_upstream_client(gateway_host: str, gateway_port: int, hmac_key: str):
    uri = f"ws://{gateway_host}:{gateway_port}"
    while True:
        try:
            logger.info("Connecting to gateway upstream at %s ...", uri)
            async with websockets.connect(uri) as ws:
                logger.info("Connected to gateway upstream.")
                async for message in ws:
                    try:
                        peek = json.loads(message)
                    except json.JSONDecodeError:
                        logger.warning("Non-JSON upstream message, dropping.")
                        continue

                    if "channels" in peek:
                        clean = verify_and_strip(message, hmac_key)
                        if clean is None:
                            await emit_integrity_violation(peek.get("device_id", "?"))
                            continue
                        await broadcast(clean)
                    else:
                        await broadcast(message)
        except (OSError, websockets.ConnectionClosed, websockets.InvalidHandshake) as e:
            logger.warning("Upstream connection lost (%s), retrying in 2s.", e)
        except Exception:
            logger.exception("Unexpected upstream error, retrying in 2s.")
        await asyncio.sleep(2)


async def run_hub(
    mode: str,
    dashboard_port: int,
    hmac_key: str | None,
    upstream_port: int | None,
    gateway_host: str,
    gateway_port: int,
):
    dashboard_server = await websockets.serve(dashboard_handler, "0.0.0.0", dashboard_port)
    logger.info("Hub dashboard server listening on port %d.", dashboard_port)

    if mode == "baseline":
        async def _handler(ws):
            await baseline_upstream_handler(ws, mode, hmac_key)

        upstream_server = await websockets.serve(_handler, "0.0.0.0", upstream_port)
        logger.info(
            "Hub upstream server listening on port %d (mode=baseline).", upstream_port
        )
        await asyncio.gather(
            upstream_server.wait_closed(),
            dashboard_server.wait_closed(),
        )
    else:
        upstream_task = asyncio.ensure_future(
            secured_upstream_client(gateway_host, gateway_port, hmac_key)
        )
        logger.info(
            "Hub upstream client targeting %s:%d (mode=secured).",
            gateway_host,
            gateway_port,
        )
        await asyncio.gather(
            upstream_task,
            dashboard_server.wait_closed(),
        )


def main():
    parser = argparse.ArgumentParser(description="BCI Processing Hub")
    parser.add_argument(
        "--mode",
        choices=["baseline", "secured"],
        default="baseline",
        help="Operating mode",
    )
    parser.add_argument(
        "--port", type=int, default=8001,
        help="Upstream listen port (baseline mode only)",
    )
    parser.add_argument("--dashboard-port", type=int, default=8002, help="Dashboard WebSocket port")
    parser.add_argument("--hmac-key", default=None, help="HMAC key for secured mode")
    parser.add_argument(
        "--gateway-host", default="localhost",
        help="Gateway hostname for secured mode upstream client",
    )
    parser.add_argument(
        "--gateway-port", type=int, default=9001,
        help="Gateway outbound port for secured mode upstream client",
    )
    parser.add_argument("--config", default=None, help="Path to config.json")

    args = parser.parse_args()

    if args.config:
        with open(args.config) as f:
            cfg = json.load(f).get("hub", {})
        if args.port == 8001 and "port" in cfg:
            args.port = cfg["port"]
        if args.dashboard_port == 8002 and "dashboard_port" in cfg:
            args.dashboard_port = cfg["dashboard_port"]
        if args.hmac_key is None and "hmac_key" in cfg:
            args.hmac_key = cfg["hmac_key"]
        if args.gateway_host == "localhost" and "gateway_host" in cfg:
            args.gateway_host = cfg["gateway_host"]
        if args.gateway_port == 9001 and "gateway_port" in cfg:
            args.gateway_port = cfg["gateway_port"]

    if args.mode == "secured" and not args.hmac_key:
        parser.error("--hmac-key is required in secured mode (or set in config.json)")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    logger.info("Starting hub in %s mode...", args.mode)
    asyncio.run(
        run_hub(
            mode=args.mode,
            dashboard_port=args.dashboard_port,
            hmac_key=args.hmac_key,
            upstream_port=args.port,
            gateway_host=args.gateway_host,
            gateway_port=args.gateway_port,
        )
    )


if __name__ == "__main__":
    main()
