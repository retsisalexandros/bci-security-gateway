"""ATK5: malformed-input fuzzing (authenticated but misbehaving device)."""
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


def _now() -> int:
    return int(time.time() * 1000)


def _malformed_battery() -> list[tuple[str, str]]:
    return [
        ("non_json", "this is not json at all {{{"),
        ("json_array", "[1, 2, 3]"),
        ("json_number", "12345"),
        ("missing_seq", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "channels": [0.0] * 8, "command": "idle"})),
        ("missing_timestamp", json.dumps({"device_id": "bci-device-001", "seq": 5, "channels": [0.0] * 8, "command": "idle"})),
        ("missing_channels", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "seq": 6, "command": "idle"})),
        ("negative_seq", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "seq": -1, "channels": [0.0] * 8, "command": "idle"})),
        ("seq_string", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "seq": "abc", "channels": [0.0] * 8, "command": "idle"})),
        ("seq_float", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "seq": 1.5, "channels": [0.0] * 8, "command": "idle"})),
        ("seq_bool", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "seq": True, "channels": [0.0] * 8, "command": "idle"})),
        ("timestamp_string", json.dumps({"device_id": "bci-device-001", "timestamp": "now", "seq": 8, "channels": [0.0] * 8, "command": "idle"})),
        ("timestamp_null", json.dumps({"device_id": "bci-device-001", "timestamp": None, "seq": 9, "channels": [0.0] * 8, "command": "idle"})),
        ("channels_string", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "seq": 10, "channels": "notalist", "command": "idle"})),
        ("channels_oversize", json.dumps({"device_id": "bci-device-001", "timestamp": _now(), "seq": 11, "channels": [0.0] * 100, "command": "idle"})),
    ]


def _valid_battery() -> list[tuple[str, str]]:
    out = []
    for seq in range(5):
        device_id = "bci-device-001"
        channels = [0.5] * 8
        command = "idle"
        if seq == 1:
            command = "コマンド"  # non-ASCII command (device_id must match the cert CN)
        if seq == 2:
            channels = [0.1] * 32  # boundary: exactly MAX_CHANNELS
        if seq == 4:
            command = "select_X"
        out.append((
            f"valid_{seq}",
            json.dumps({
                "device_id": device_id,
                "timestamp": _now(),
                "seq": seq,
                "channels": channels,
                "command": command,
            }),
        ))
    return out


def _build_ssl(cert: str, key: str, ca_cert: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_cert)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def run_fuzz(
    host: str,
    port: int,
    gateway_log: str = "gateway_events.log",
    cert: str = "certs/devices/device-001.crt",
    key: str = "certs/devices/device-001.key",
    ca_cert: str = "certs/ca/testbed-ca.crt",
    device_id: str = "bci-device-001",
):
    uri = f"wss://{host}:{port}"
    ssl_ctx = _build_ssl(cert, key, ca_cert)
    malformed = _malformed_battery()
    valid = _valid_battery()

    window_start = _now()
    connection_dropped = False
    sent_malformed = 0
    sent_valid = 0

    print(f"  sending {len(malformed)} malformed then {len(valid)} valid packets")
    try:
        async with websockets.connect(uri, ssl=ssl_ctx) as ws:
            for _label, raw in malformed:
                await ws.send(raw)
                sent_malformed += 1
                await asyncio.sleep(0.02)
            for _label, raw in valid:
                await ws.send(raw)
                sent_valid += 1
                await asyncio.sleep(0.02)
    except websockets.ConnectionClosed:
        connection_dropped = True
        print("  connection dropped mid-fuzz (gateway closed the device handler)")
    except Exception as e:
        print(f"  error: {e}")
        connection_dropped = True

    await asyncio.sleep(0.5)
    window_end = _now()

    events = read_gateway_events(gateway_log)
    scoped = events_in_window(events, window_start - 500, window_end + 1500)
    rejected = count_events(scoped, "packet_rejected", device_id=device_id)
    forwarded = count_events(scoped, "packet_forwarded", device_id=device_id)

    survived = (not connection_dropped) and forwarded == len(valid)
    all_malformed_rejected = rejected >= len(malformed)

    return {
        "attack": "ATK5_fuzz",
        "attacker_model": "authenticated but misbehaving device sending malformed packets",
        "blocked_by": "input validation (packet-shape check before F2/F3)",
        "params": {"malformed_count": len(malformed), "valid_count": len(valid)},
        "attacker_view": {
            "malformed_sent": sent_malformed,
            "valid_sent": sent_valid,
            "connection_dropped": connection_dropped,
        },
        "defender_view": {
            "log_path": gateway_log,
            "packet_rejected": rejected,
            "packet_forwarded": forwarded,
            "window_ms": [window_start, window_end],
        },
        "success_criterion_met": survived and all_malformed_rejected,
    }


def main():
    parser = argparse.ArgumentParser(description="ATK5: malformed-input fuzzing")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--cert", default="certs/devices/device-001.crt")
    parser.add_argument("--key", default="certs/devices/device-001.key")
    parser.add_argument("--ca-cert", default="certs/ca/testbed-ca.crt")
    parser.add_argument("--gateway-log", default="gateway_events.log")
    args = parser.parse_args()

    print("ATK5 malformed-input fuzzing")
    results = asyncio.run(run_fuzz(
        args.host, args.port, args.gateway_log, args.cert, args.key, args.ca_cert,
    ))
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
