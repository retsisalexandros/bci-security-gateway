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


async def _rate_flood(uri: str, ssl_ctx, count: int, gateway_log: str, device_id: str) -> dict:
    print(f"  [rate_flood] sending {count} packets as fast as possible")
    win_start = _now_ms()
    sent = 0
    try:
        async with websockets.connect(uri, ssl=ssl_ctx) as ws:
            for i in range(count):
                raw = json.dumps({
                    "device_id": device_id,
                    "timestamp": _now_ms(),
                    "seq": i,
                    "channels": [0.0] * 8,
                    "command": "idle",
                })
                try:
                    await ws.send(raw)
                    sent += 1
                except websockets.ConnectionClosed:
                    break
    except Exception as e:
        print(f"  [rate_flood] connection error: {e}")
    win_end = _now_ms()

    events = read_gateway_events(gateway_log)
    scoped = events_in_window(events, win_start - 200, win_end + 1500)
    rate_limited = count_events(scoped, "rate_limited", device_id=device_id)
    forwarded = count_events(scoped, "packet_forwarded", device_id=device_id)
    return {
        "description": "authenticated device floods packets above the gateway rate cap",
        "sent": sent,
        "defender": {
            "rate_limited": rate_limited,
            "packet_forwarded": forwarded,
            "window_ms": [win_start, win_end],
        },
        "blocked": rate_limited > 0 and sent > 0,
    }


async def _abnormal_channels(
    uri: str, ssl_ctx, baseline_packets: int, anomalous_packets: int,
    anomalous_value: float, gateway_log: str, device_id: str,
) -> dict:
    print(f"  [abnormal_channels] {baseline_packets} normal then {anomalous_packets} anomalous")
    import random
    rng = random.Random(7)

    batch = 10
    pace = 0.05

    async def send_paced(ws, packets):
        sent = 0
        for i, raw in enumerate(packets):
            try:
                await ws.send(raw)
                sent += 1
            except websockets.ConnectionClosed:
                break
            if (i + 1) % batch == 0:
                await asyncio.sleep(pace)
        return sent

    win_start = _now_ms()
    seq = 0
    baseline_sent = 0
    anomalous_sent = 0
    anomalous_start = win_start
    try:
        async with websockets.connect(uri, ssl=ssl_ctx) as ws:
            normal = []
            for _ in range(baseline_packets):
                normal.append(json.dumps({
                    "device_id": device_id,
                    "timestamp": _now_ms(),
                    "seq": seq,
                    "channels": [round(rng.gauss(0, 20), 2) for _ in range(8)],
                    "command": "idle",
                }))
                seq += 1
            baseline_sent = await send_paced(ws, normal)

            await asyncio.sleep(0.2)
            anomalous_start = _now_ms()
            abnormal = []
            for _ in range(anomalous_packets):
                abnormal.append(json.dumps({
                    "device_id": device_id,
                    "timestamp": _now_ms(),
                    "seq": seq,
                    "channels": [anomalous_value] * 8,
                    "command": "idle",
                }))
                seq += 1
            anomalous_sent = await send_paced(ws, abnormal)
    except Exception as e:
        print(f"  [abnormal_channels] connection error: {e}")
    win_end = _now_ms()

    events = read_gateway_events(gateway_log)
    scoped = events_in_window(events, anomalous_start - 200, win_end + 1500)
    detected = count_events(scoped, "anomaly_detected", device_id=device_id)
    return {
        "description": "authenticated device sends channel values far outside its learned baseline",
        "baseline_sent": baseline_sent,
        "anomalous_sent": anomalous_sent,
        "anomalous_value": anomalous_value,
        "defender": {
            "anomaly_detected": detected,
            "window_ms": [anomalous_start, win_end],
        },
        "note": "F4 anomaly detection is alert-only: the packets are still forwarded but flagged",
        "blocked": anomalous_sent > 0 and detected >= anomalous_sent,
    }


async def run_abnormal(
    host: str,
    port: int,
    cert: str,
    key: str,
    ca_cert: str,
    flood_count: int,
    baseline_packets: int,
    anomalous_packets: int,
    anomalous_value: float,
    baseline: bool,
    gateway_log: str,
    device_id: str = "bci-device-001",
):
    if baseline:
        return {
            "attack": "ATK6_abnormal_device",
            "skipped": True,
            "reason": "baseline mode has no rate limiter or anomaly detector",
        }

    uri = f"wss://{host}:{port}"
    ssl_ctx = _build_ssl(cert, key, ca_cert)

    variants: dict = {}
    variants["rate_flood"] = await _rate_flood(
        uri, ssl_ctx, flood_count, gateway_log, device_id,
    )
    variants["abnormal_channels"] = await _abnormal_channels(
        uri, ssl_ctx, baseline_packets, anomalous_packets, anomalous_value,
        gateway_log, device_id,
    )

    return {
        "attack": "ATK6_abnormal_device",
        "attacker_model": "authenticated but misbehaving device: holds a valid cert, floods packets and emits out-of-distribution channel values",
        "blocked_by": "F4 (packet-rate limiting + behavioural anomaly detection)",
        "params": {
            "flood_count": flood_count,
            "baseline_packets": baseline_packets,
            "anomalous_packets": anomalous_packets,
            "anomalous_value": anomalous_value,
            "device_id": device_id,
        },
        "variants": variants,
        "defender_view": {
            "log_path": gateway_log,
            "note": "rate_flood is dropped by the rate limiter (prevention); "
                    "abnormal_channels is flagged by the behavioural detector (alert-only detection)",
        },
        "success_criterion_met": all(v["blocked"] for v in variants.values()),
    }


def main():
    parser = argparse.ArgumentParser(description="ATK6: abnormal authenticated device")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--cert", default="certs/devices/device-001.crt")
    parser.add_argument("--key", default="certs/devices/device-001.key")
    parser.add_argument("--ca-cert", default="certs/ca/testbed-ca.crt")
    parser.add_argument("--flood-count", type=int, default=1500)
    parser.add_argument("--baseline-packets", type=int, default=350)
    parser.add_argument("--anomalous-packets", type=int, default=100)
    parser.add_argument("--anomalous-value", type=float, default=250.0)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--gateway-log", default="gateway_events.log")
    parser.add_argument("--device-id", default="bci-device-001")
    args = parser.parse_args()

    print(f"ATK6 abnormal device, flood={args.flood_count} anomalous={args.anomalous_packets}")
    results = asyncio.run(run_abnormal(
        host=args.host, port=args.port, cert=args.cert, key=args.key,
        ca_cert=args.ca_cert, flood_count=args.flood_count,
        baseline_packets=args.baseline_packets, anomalous_packets=args.anomalous_packets,
        anomalous_value=args.anomalous_value, baseline=args.baseline,
        gateway_log=args.gateway_log, device_id=args.device_id,
    ))
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
