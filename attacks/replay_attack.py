"""ATK2: replay attack (compromised-device model): delayed and in-session."""
from __future__ import annotations

import ssl
import json
import time
import argparse
import asyncio
import os
import sys

import websockets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks._logreader import read_gateway_events, events_in_window, count_events


def _now_ms() -> int:
    return int(time.time() * 1000)


def _build_ssl(cert: str, key: str, ca_cert: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_cert)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _delayed_replay(
    uri: str, ssl_ctx, count: int, delay: float,
    baseline: bool, gateway_log: str, device_id: str,
) -> dict:
    captured: list[str] = []
    print(f"  [delayed_replay] capturing {count} packets")
    async with websockets.connect(uri, ssl=ssl_ctx) as ws:
        for i in range(count):
            raw = json.dumps({
                "device_id": device_id,
                "timestamp": _now_ms(),
                "seq": i,
                "channels": [1.0 * i] * 8,
                "command": "idle",
            })
            await ws.send(raw)
            captured.append(raw)
            await asyncio.sleep(0.01)

    print(f"  [delayed_replay] waiting {delay}s (gateway window is ~5s)")
    await asyncio.sleep(delay)

    replay_start = _now_ms()
    sent = 0
    print("  [delayed_replay] replaying verbatim on a fresh connection")
    try:
        async with websockets.connect(uri, ssl=ssl_ctx) as ws:
            for raw in captured:
                try:
                    await ws.send(raw)
                    sent += 1
                    await asyncio.sleep(0.01)
                except websockets.ConnectionClosed:
                    break
    except Exception as e:
        print(f"  [delayed_replay] replay connection error: {e}")
    replay_end = _now_ms()

    variant: dict = {
        "description": "replay verbatim after the time window expires",
        "captured": len(captured),
        "replayed_sent": sent,
    }
    if baseline:
        variant["defender"] = {"skipped": True, "note": "baseline pipeline has no anti-replay"}
        variant["blocked"] = False
        return variant

    events = read_gateway_events(gateway_log)
    scoped = events_in_window(events, replay_start - 500, replay_end + 1500)
    stale = count_events(scoped, "replay_rejected", "stale_timestamp", device_id=device_id)
    dup = count_events(scoped, "replay_rejected", "duplicate_seq", device_id=device_id)
    forwarded = count_events(scoped, "packet_forwarded", device_id=device_id)
    variant["defender"] = {
        "replay_rejected_stale_timestamp": stale,
        "replay_rejected_duplicate_seq": dup,
        "packet_forwarded_during_replay": forwarded,
        "window_ms": [replay_start, replay_end],
    }
    variant["blocked"] = sent > 0 and forwarded == 0 and stale >= sent
    return variant


async def _in_session_replay(
    uri: str, ssl_ctx, count: int, gateway_log: str, device_id: str,
) -> dict:
    print(f"  [in_session_replay] sending {count} packets then resending the same bytes")
    win_start = _now_ms()
    sent_first = 0
    resent = 0
    try:
        async with websockets.connect(uri, ssl=ssl_ctx) as ws:
            raws: list[str] = []
            for i in range(count):
                raw = json.dumps({
                    "device_id": device_id,
                    "timestamp": _now_ms(),
                    "seq": i,
                    "channels": [2.0 * i] * 8,
                    "command": "idle",
                })
                await ws.send(raw)
                raws.append(raw)
                sent_first += 1
                await asyncio.sleep(0.005)
            for raw in raws:
                try:
                    await ws.send(raw)
                    resent += 1
                    await asyncio.sleep(0.005)
                except websockets.ConnectionClosed:
                    break
    except Exception as e:
        print(f"  [in_session_replay] connection error: {e}")
    win_end = _now_ms()

    events = read_gateway_events(gateway_log)
    scoped = events_in_window(events, win_start - 200, win_end + 1500)
    dup = count_events(scoped, "replay_rejected", "duplicate_seq", device_id=device_id)
    forwarded = count_events(scoped, "packet_forwarded", device_id=device_id)
    return {
        "description": "resend the same packets within the time window on one connection",
        "sent_first_pass": sent_first,
        "resent": resent,
        "defender": {
            "replay_rejected_duplicate_seq": dup,
            "packet_forwarded": forwarded,
            "window_ms": [win_start, win_end],
        },
        "blocked": forwarded == sent_first and dup >= resent and resent > 0,
    }


async def run_replay(
    host: str,
    port: int,
    cert: str,
    key: str,
    ca_cert: str,
    capture_count: int,
    delay: float,
    baseline: bool,
    gateway_log: str,
    device_id: str = "bci-device-001",
):
    scheme = "ws" if baseline else "wss"
    uri = f"{scheme}://{host}:{port}"
    ssl_ctx = None if baseline else _build_ssl(cert, key, ca_cert)

    variants: dict = {}
    variants["delayed_replay"] = await _delayed_replay(
        uri, ssl_ctx, capture_count, delay, baseline, gateway_log, device_id,
    )
    if not baseline:
        variants["in_session_replay"] = await _in_session_replay(
            uri, ssl_ctx, capture_count, gateway_log, device_id,
        )

    return {
        "attack": "ATK2_replay",
        "attacker_model": "compromised device: adversary holds device-001's extracted cert and private key",
        "blocked_by": "F3 (timestamp window + strictly-increasing sequence numbers)",
        "params": {"capture_count": capture_count, "delay_seconds": delay, "device_id": device_id},
        "variants": variants,
        "defender_view": {
            "log_path": None if baseline else gateway_log,
            "note": "baseline pipeline has no gateway and no anti-replay"
            if baseline
            else "delayed replays are caught by the stale-timestamp branch, "
                 "in-session resends by the duplicate-sequence branch",
        },
        "success_criterion_met": (
            not baseline and all(v["blocked"] for v in variants.values())
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="ATK2: replay attack")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--cert", default="certs/devices/device-001.crt")
    parser.add_argument("--key", default="certs/devices/device-001.key")
    parser.add_argument("--ca-cert", default="certs/ca/testbed-ca.crt")
    parser.add_argument("--capture-count", type=int, default=100)
    parser.add_argument("--delay", type=float, default=8.0,
                        help="Seconds between capture and replay (must exceed the gateway window)")
    parser.add_argument("--baseline", action="store_true",
                        help="Target the baseline hub directly (no TLS, no defences)")
    parser.add_argument("--no-tls", dest="baseline", action="store_true",
                        help="Deprecated alias for --baseline")
    parser.add_argument("--gateway-log", default="gateway_events.log")
    parser.add_argument("--device-id", default="bci-device-001")
    args = parser.parse_args()

    print(f"ATK2 replay, capture={args.capture_count} delay={args.delay}s")
    results = asyncio.run(run_replay(
        host=args.host, port=args.port, cert=args.cert, key=args.key,
        ca_cert=args.ca_cert, capture_count=args.capture_count, delay=args.delay,
        baseline=args.baseline, gateway_log=args.gateway_log, device_id=args.device_id,
    ))
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
