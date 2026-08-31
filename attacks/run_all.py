"""Attack orchestrator: runs ATK1-ATK5 and writes a combined JSON report."""
from __future__ import annotations

import json
import argparse
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks.spoof_device import run_spoof
from attacks.replay_attack import run_replay
from attacks.tamper_mitm import run_tamper
from attacks.unauth_access import run_unauth
from attacks.fuzz_input import run_fuzz
from attacks.abnormal_device import run_abnormal

CERT = "certs/devices/device-001.crt"
KEY = "certs/devices/device-001.key"
CA = "certs/ca/testbed-ca.crt"


async def run_all(args) -> dict:
    results: dict = {}

    print("\n-- ATK1: device spoofing --")
    if args.baseline:
        results["ATK1_spoof"] = {"skipped": True, "reason": "baseline mode has no mTLS layer"}
        print("  SKIPPED (baseline mode)")
    else:
        results["ATK1_spoof"] = await run_spoof(
            args.host, args.gateway_port, attempts=args.attempts,
            gateway_log=args.gateway_log,
        )

    print("\n-- ATK2: replay --")
    results["ATK2_replay"] = await run_replay(
        host=args.host,
        port=args.hub_port if args.baseline else args.gateway_port,
        cert=CERT, key=KEY, ca_cert=CA,
        capture_count=args.capture_count, delay=args.replay_delay,
        baseline=args.baseline, gateway_log=args.gateway_log,
    )

    print("\n-- ATK3: tampering / on-path MitM --")
    results["ATK3_tamper"] = await run_tamper(
        host=args.host, port=args.hub_port, num_packets=args.tamper_packets,
        use_hmac=not args.baseline, hmac_key=args.hmac_key,
        gateway_host=args.host, gateway_port=args.gateway_outbound_port,
        gateway_inbound_port=args.gateway_port,
        cert=CERT, key=KEY, ca_cert=CA,
        mitm_listen_port=args.mitm_listen_port,
        sidecar_dashboard_port=args.sidecar_dashboard_port,
        feed_packets=args.mitm_feed_packets,
    )

    print("\n-- ATK4: unauthorised access --")
    if args.baseline:
        results["ATK4_unauth"] = {"skipped": True, "reason": "baseline mode has no allowlist"}
        print("  SKIPPED (baseline mode)")
    else:
        results["ATK4_unauth"] = await run_unauth(
            args.host, args.gateway_port, attempts=args.attempts,
            ca_cert=CA, gateway_log=args.gateway_log,
        )

    print("\n-- ATK5: malformed-input fuzzing --")
    if args.baseline:
        results["ATK5_fuzz"] = {"skipped": True, "reason": "baseline mode has no input-validation layer"}
        print("  SKIPPED (baseline mode)")
    else:
        results["ATK5_fuzz"] = await run_fuzz(
            args.host, args.gateway_port, gateway_log=args.gateway_log,
            cert=CERT, key=KEY, ca_cert=CA,
        )

    print("\n-- ATK6: abnormal authenticated device --")
    if args.baseline:
        results["ATK6_abnormal"] = {"skipped": True, "reason": "baseline mode has no rate limiter or anomaly detector"}
        print("  SKIPPED (baseline mode)")
    else:
        results["ATK6_abnormal"] = await run_abnormal(
            host=args.host, port=args.gateway_port,
            cert=CERT, key=KEY, ca_cert=CA,
            flood_count=args.flood_count,
            baseline_packets=args.anomaly_baseline_packets,
            anomalous_packets=args.anomaly_packets,
            anomalous_value=args.anomaly_value,
            baseline=args.baseline, gateway_log=args.gateway_log,
        )

    return results


def _summary_line(name: str, r: dict) -> str:
    if r.get("skipped"):
        return f"  {name}: SKIPPED ({r.get('reason')})"
    flags = []
    for vname, v in r.get("variants", {}).items():
        flags.append(f"{vname}={'blocked' if v.get('blocked') else 'NOT-BLOCKED'}")
    met = r.get("success_criterion_met")
    return f"  {name}: success_criterion_met={met}  [{', '.join(flags)}]"


def main():
    parser = argparse.ArgumentParser(description="BCI attack orchestrator")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=9000,
                        help="Gateway inbound (mTLS) port")
    parser.add_argument("--gateway-outbound-port", type=int, default=9001,
                        help="Gateway outbound (hub-facing) port")
    parser.add_argument("--hub-port", type=int, default=8001,
                        help="Hub upstream port (baseline only)")
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--attempts", type=int, default=100,
                        help="Attempts per variant for ATK1/ATK4")
    parser.add_argument("--capture-count", type=int, default=100,
                        help="Packets per batch for ATK2")
    parser.add_argument("--replay-delay", type=float, default=8.0,
                        help="ATK2 delayed-replay wait (must exceed the gateway window)")
    parser.add_argument("--tamper-packets", type=int, default=20,
                        help="Forged packet count for ATK3 baseline mode")
    parser.add_argument("--mitm-listen-port", type=int, default=9101)
    parser.add_argument("--sidecar-dashboard-port", type=int, default=8003)
    parser.add_argument("--mitm-feed-packets", type=int, default=800)
    parser.add_argument("--flood-count", type=int, default=1500,
                        help="ATK6 rate-flood packet count")
    parser.add_argument("--anomaly-baseline-packets", type=int, default=350,
                        help="ATK6 normal packets sent before anomalous ones")
    parser.add_argument("--anomaly-packets", type=int, default=100,
                        help="ATK6 anomalous packet count")
    parser.add_argument("--anomaly-value", type=float, default=250.0,
                        help="ATK6 anomalous channel value")
    parser.add_argument("--hmac-key", default="super-secret-hmac-key-for-prototype")
    parser.add_argument("--gateway-log", default="gateway_events.log")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    mode = "baseline" if args.baseline else "secured"
    print(f"BCI attack suite ({mode})")

    results = asyncio.run(run_all(args))

    print("\n-- summary --")
    for name, r in results.items():
        print(_summary_line(name, r))

    output_path = args.output or f"evaluation/results/attack_results_{mode}.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nsaved to {output_path}")


if __name__ == "__main__":
    main()
