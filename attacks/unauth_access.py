"""ATK4: unauthorised access (valid cert, non-allowlisted CN)."""
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
from attacks._stats import rate_with_ci

VARIANTS = [
    (
        "non_allowlisted",
        "bci-device-002",
        "valid testbed-CA cert for a provisioned but non-allowlisted device",
        "certs/devices/device-002.crt",
        "certs/devices/device-002.key",
    ),
    (
        "case_mismatch",
        "BCI-DEVICE-001",
        "CN differs from an allowlisted id only by letter case",
        "certs/devices/device-upper.crt",
        "certs/devices/device-upper.key",
    ),
    (
        "cn_substring",
        "bci-device-001-rogue",
        "CN contains an allowlisted id as a substring",
        "certs/devices/device-substr.crt",
        "certs/devices/device-substr.key",
    ),
]


def _client_ctx(cert: str, key: str, ca_cert: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_cert)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _one_attempt(uri: str, ctx: ssl.SSLContext, device_id: str, seq: int) -> str:
    try:
        async with websockets.connect(uri, ssl=ctx) as ws:
            await ws.send(json.dumps({
                "device_id": device_id,
                "timestamp": int(time.time() * 1000),
                "seq": seq,
                "channels": [0.0] * 8,
                "command": "idle",
            }))
            # gateway closes 1008 after the allowlist check; still-open = got through
            try:
                await asyncio.wait_for(ws.recv(), timeout=2.0)
                return "connected"
            except asyncio.TimeoutError:
                return "connected"
    except websockets.ConnectionClosed:
        return "rejected"
    except ssl.SSLError:
        return "tls_error"
    except Exception:
        return "error"


async def _run_variant(uri: str, ctx_args, device_id: str, attempts: int) -> dict:
    tally = {"connected": 0, "rejected": 0, "tls_error": 0, "error": 0}
    for i in range(attempts):
        ctx = _client_ctx(*ctx_args)
        tally[await _one_attempt(uri, ctx, device_id, i * 10)] += 1
    return tally


async def run_unauth(
    host: str,
    port: int,
    attempts: int,
    ca_cert: str = "certs/ca/testbed-ca.crt",
    gateway_log: str = "gateway_events.log",
):
    uri = f"wss://{host}:{port}"
    window_start = int(time.time() * 1000)

    variants: dict = {}
    for name, cn, desc, cert, key in VARIANTS:
        print(f"  [{name}] {attempts} attempts as CN={cn}: {desc}")
        tally = await _run_variant(uri, (cert, key, ca_cert), cn, attempts)
        blocked = tally["connected"] == 0 and tally["rejected"] >= attempts
        variants[name] = {
            "common_name": cn,
            "description": desc,
            "attempts": attempts,
            **tally,
            "connection_success": rate_with_ci(tally["connected"], attempts),
            "blocked": blocked,
        }
        print(f"    connected={tally['connected']} rejected={tally['rejected']} blocked={blocked}")

    window_end = int(time.time() * 1000)

    events = read_gateway_events(gateway_log)
    scoped = events_in_window(events, window_start - 500, window_end + 1500)
    defender: dict = {"log_path": gateway_log, "window_ms": [window_start, window_end]}
    all_logged = True
    for name, cn, _desc, _cert, _key in VARIANTS:
        rejects = count_events(scoped, "auth_failure", "Not in allowlist", device_id=cn)
        successes = count_events(scoped, "auth_success", device_id=cn)
        defender[name] = {
            "common_name": cn,
            "auth_failure_not_in_allowlist": rejects,
            "auth_success": successes,
        }
        if rejects < attempts or successes != 0:
            all_logged = False

    return {
        "attack": "ATK4_unauth",
        "attacker_model": "rogue device with a validly signed cert whose CN is not allowlisted",
        "blocked_by": "F1 (allowlist check on certificate CN)",
        "params": {"attempts": attempts},
        "variants": variants,
        "defender_view": defender,
        "success_criterion_met": (
            all(v["blocked"] for v in variants.values()) and all_logged
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="ATK4: unauthorised access")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--ca-cert", default="certs/ca/testbed-ca.crt")
    parser.add_argument("--gateway-log", default="gateway_events.log")
    args = parser.parse_args()

    print(f"ATK4 unauthorised access, {args.attempts} attempts per variant")
    results = asyncio.run(run_unauth(
        args.host, args.port, args.attempts, args.ca_cert, args.gateway_log,
    ))
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
