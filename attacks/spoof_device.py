"""ATK1: device spoofing (untrusted CA, expired cert, no client cert)."""
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
        "untrusted_ca",
        "client cert signed by an untrusted (attacker) CA",
        "certs/attacker/attacker.crt",
        "certs/attacker/attacker.key",
    ),
    (
        "expired_cert",
        "client cert chains to the testbed CA but has expired",
        "certs/devices/device-expired.crt",
        "certs/devices/device-expired.key",
    ),
    (
        "no_client_cert",
        "no client certificate presented",
        None,
        None,
    ),
]


def _client_ctx(cert: str | None, key: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def _classify(exc: Exception) -> str:
    # refused = gateway unreachable; anything else = handshake rejected by the gateway
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    return "rejected"


async def _one_attempt(uri: str, ctx: ssl.SSLContext, seq: int) -> tuple[str, str | None]:
    try:
        async with websockets.connect(uri, ssl=ctx) as ws:
            await ws.send(json.dumps({
                "device_id": "spoofed-device",
                "timestamp": int(time.time() * 1000),
                "seq": seq,
                "channels": [0.0] * 8,
                "command": "idle",
            }))
            return "connected", None
    except Exception as exc:
        return _classify(exc), f"{type(exc).__name__}: {exc}"


async def _run_variant(
    uri: str, cert: str | None, key: str | None, attempts: int,
) -> tuple[dict, str | None]:
    tally = {"connected": 0, "rejected": 0, "refused": 0}
    example = None
    for i in range(attempts):
        ctx = _client_ctx(cert, key)
        category, detail = await _one_attempt(uri, ctx, i)
        tally[category] += 1
        if category == "rejected" and example is None:
            example = detail
    return tally, example


async def run_spoof(
    host: str,
    port: int,
    attempts: int,
    gateway_log: str = "gateway_events.log",
):
    uri = f"wss://{host}:{port}"
    window_start = int(time.time() * 1000)

    variants: dict = {}
    for name, desc, cert, key in VARIANTS:
        print(f"  [{name}] {attempts} attempts: {desc}")
        tally, example = await _run_variant(uri, cert, key, attempts)
        blocked = tally["connected"] == 0 and tally["rejected"] >= attempts
        variants[name] = {
            "description": desc,
            "attempts": attempts,
            **tally,
            "example_rejection": example,
            "connection_success": rate_with_ci(tally["connected"], attempts),
            "blocked": blocked,
        }
        print(f"    connected={tally['connected']} rejected={tally['rejected']} "
              f"refused={tally['refused']} blocked={blocked}")

    window_end = int(time.time() * 1000)

    events = read_gateway_events(gateway_log)
    scoped = events_in_window(events, window_start - 500, window_end + 1500)
    auth_success = count_events(scoped, "auth_success")
    auth_failure = count_events(scoped, "auth_failure")

    return {
        "attack": "ATK1_spoof",
        "attacker_model": "rogue device presenting a certificate the gateway must reject at the mTLS layer",
        "blocked_by": "F1 (mTLS certificate-chain and validity verification)",
        "params": {"attempts": attempts},
        "variants": variants,
        "defender_view": {
            "log_path": gateway_log,
            "note": "TLS handshakes fail below the gateway's application logger; "
                    "rejection is observed attacker-side. With no legitimate "
                    "device connected during the attack window, the gateway "
                    "should emit zero auth events.",
            "auth_success_in_window": auth_success,
            "auth_failure_in_window": auth_failure,
            "window_ms": [window_start, window_end],
        },
        "success_criterion_met": (
            all(v["blocked"] for v in variants.values())
            and auth_success == 0
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="ATK1: device spoofing")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--attempts", type=int, default=100)
    parser.add_argument("--gateway-log", default="gateway_events.log")
    args = parser.parse_args()

    print(f"ATK1 spoofing, {args.attempts} attempts per variant")
    results = asyncio.run(run_spoof(args.host, args.port, args.attempts, args.gateway_log))
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
