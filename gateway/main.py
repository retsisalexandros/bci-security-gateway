from __future__ import annotations

import argparse
import asyncio
import json
import logging

import websockets

from .auth import build_ssl_context
from .proxy import GatewayProxy
from .logger import EventLogger

logger = logging.getLogger(__name__)


async def metrics_loop(proxy: GatewayProxy):
    while True:
        await asyncio.sleep(2)
        while proxy.event_logger.event_queue:
            event = proxy.event_logger.event_queue.popleft()
            await proxy.broadcast_event(event)
        await proxy.broadcast_metrics()


async def run_gateway(
    inbound_port: int,
    outbound_port: int,
    ssl_ctx,
    proxy: GatewayProxy,
):
    inbound = await websockets.serve(
        proxy.handle_device, "0.0.0.0", inbound_port, ssl=ssl_ctx
    )
    logger.info("Gateway inbound (device) server on port %d (mTLS).", inbound_port)

    outbound = await websockets.serve(
        proxy.handle_hub, "0.0.0.0", outbound_port
    )
    logger.info("Gateway outbound (hub) server on port %d.", outbound_port)

    metrics_task = asyncio.ensure_future(metrics_loop(proxy))

    await asyncio.gather(
        inbound.wait_closed(),
        outbound.wait_closed(),
        metrics_task,
    )


def main():
    parser = argparse.ArgumentParser(description="BCI Security Gateway")
    parser.add_argument("--port", type=int, default=9000, help="Inbound (device) port")
    parser.add_argument("--outbound-port", type=int, default=9001, help="Outbound (hub) port")
    parser.add_argument("--server-cert", default=None)
    parser.add_argument("--server-key", default=None)
    parser.add_argument("--ca-cert", default=None)
    parser.add_argument("--hmac-key", default=None)
    parser.add_argument("--time-window", type=float, default=5.0, help="Anti-replay time window (seconds)")
    parser.add_argument("--max-pps", type=float, default=400.0, help="F4 packet-rate cap per device")
    parser.add_argument("--anomaly-learn-samples", type=int, default=300, help="F4 packets to learn baseline")
    parser.add_argument("--anomaly-z", type=float, default=6.0, help="F4 z-score threshold")
    parser.add_argument("--channel-bound", type=float, default=300.0, help="F4 hard channel value bound")
    parser.add_argument("--allowlist", default=None, help="Comma-separated device IDs")
    parser.add_argument("--log-path", default="gateway_events.log")
    parser.add_argument("--config", default=None, help="Path to config.json")

    args = parser.parse_args()

    if args.config:
        with open(args.config) as f:
            cfg = json.load(f).get("gateway", {})
        if args.port == 9000 and "inbound_port" in cfg:
            args.port = cfg["inbound_port"]
        if args.outbound_port == 9001 and "outbound_port" in cfg:
            args.outbound_port = cfg["outbound_port"]
        if args.server_cert is None and "server_cert" in cfg:
            args.server_cert = cfg["server_cert"]
        if args.server_key is None and "server_key" in cfg:
            args.server_key = cfg["server_key"]
        if args.ca_cert is None and "ca_cert" in cfg:
            args.ca_cert = cfg["ca_cert"]
        if args.hmac_key is None and "hmac_key" in cfg:
            args.hmac_key = cfg["hmac_key"]
        if args.allowlist is None and "allowlist" in cfg:
            args.allowlist = cfg["allowlist"]
        if "time_window_seconds" in cfg:
            args.time_window = cfg["time_window_seconds"]
        if args.max_pps == 400.0 and "max_pps" in cfg:
            args.max_pps = cfg["max_pps"]
        if args.anomaly_learn_samples == 300 and "anomaly_learn_samples" in cfg:
            args.anomaly_learn_samples = cfg["anomaly_learn_samples"]
        if args.anomaly_z == 6.0 and "anomaly_z" in cfg:
            args.anomaly_z = cfg["anomaly_z"]
        if args.channel_bound == 300.0 and "channel_bound" in cfg:
            args.channel_bound = cfg["channel_bound"]
        if args.log_path == "gateway_events.log" and "log_path" in cfg:
            args.log_path = cfg["log_path"]

    missing = []
    if not args.server_cert:
        missing.append("--server-cert")
    if not args.server_key:
        missing.append("--server-key")
    if not args.ca_cert:
        missing.append("--ca-cert")
    if not args.hmac_key:
        missing.append("--hmac-key")
    if missing:
        parser.error(f"Missing required arguments: {', '.join(missing)} (or set in config.json)")

    allowlist = args.allowlist
    if isinstance(allowlist, str):
        allowlist = [x.strip() for x in allowlist.split(",")]
    if not allowlist:
        parser.error("--allowlist is required (or set in config.json)")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    event_logger = EventLogger(args.log_path)
    ssl_ctx = build_ssl_context(args.server_cert, args.server_key, args.ca_cert)

    proxy = GatewayProxy(
        allowlist=allowlist,
        hmac_key=args.hmac_key,
        time_window=args.time_window,
        event_logger=event_logger,
        max_pps=args.max_pps,
        anomaly_learn_samples=args.anomaly_learn_samples,
        anomaly_z=args.anomaly_z,
        channel_bound=args.channel_bound,
    )

    logger.info("Starting gateway...")
    try:
        asyncio.run(run_gateway(args.port, args.outbound_port, ssl_ctx, proxy))
    finally:
        event_logger.close()


if __name__ == "__main__":
    main()
