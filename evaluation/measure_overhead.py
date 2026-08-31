"""Per-packet overhead micro-benchmark: F2/F3 vs a plain JSON pass-through."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gateway.integrity import attach_hmac
from gateway.replay import ReplayDetector
from hub.verifier import verify_and_strip

HMAC_KEY = "super-secret-hmac-key-for-prototype"
INTER_PACKET_BUDGET_MS = 1000.0 / 250.0


def _pct(samples: list[float], p: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    k = (len(ordered) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _stats(samples: list[float]) -> dict:
    return {
        "mean_ms": round(sum(samples) / len(samples), 6),
        "p50_ms": round(_pct(samples, 50), 6),
        "p95_ms": round(_pct(samples, 95), 6),
        "p99_ms": round(_pct(samples, 99), 6),
        "max_ms": round(max(samples), 6),
    }


def _packet(seq: int) -> dict:
    return {
        "device_id": "bci-device-001",
        "timestamp": int(time.time() * 1000),
        "seq": seq,
        "channels": [12.3, -4.7, 8.1, -2.3, 15.6, -7.2, 3.4, -1.8],
        "command": "idle",
    }


def bench_baseline(n: int) -> list[float]:
    # parse and re-serialise only
    samples = []
    for i in range(n):
        raw = json.dumps(_packet(i))
        t0 = time.perf_counter()
        pkt = json.loads(raw)
        _ = json.dumps(pkt)
        samples.append((time.perf_counter() - t0) * 1000)
    return samples


def bench_secured(n: int) -> list[float]:
    # parse + F3 validate + F2 HMAC attach
    detector = ReplayDetector(time_window=5.0)
    samples = []
    for i in range(n):
        raw = json.dumps(_packet(i))
        t0 = time.perf_counter()
        pkt = json.loads(raw)
        detector.validate("bci-device-001", pkt["seq"], pkt["timestamp"])
        _ = attach_hmac(pkt, HMAC_KEY)
        samples.append((time.perf_counter() - t0) * 1000)
    return samples


def bench_hub_verify(n: int) -> list[float]:
    # F2 HMAC verification and metadata strip
    samples = []
    for i in range(n):
        secured = attach_hmac(_packet(i), HMAC_KEY)
        t0 = time.perf_counter()
        _ = verify_and_strip(secured, HMAC_KEY)
        samples.append((time.perf_counter() - t0) * 1000)
    return samples


def main():
    parser = argparse.ArgumentParser(description="Per-packet overhead benchmark")
    parser.add_argument("--iterations", type=int, default=50000)
    parser.add_argument("--output", default="evaluation/results/overhead.json")
    args = parser.parse_args()

    n = args.iterations
    print(f"benchmarking {n} iterations per path ...")
    baseline = _stats(bench_baseline(n))
    secured = _stats(bench_secured(n))
    hub_verify = _stats(bench_hub_verify(n))

    gateway_overhead = round(secured["mean_ms"] - baseline["mean_ms"], 6)
    report = {
        "iterations": n,
        "inter_packet_budget_ms": round(INTER_PACKET_BUDGET_MS, 4),
        "baseline_passthrough_ms": baseline,
        "secured_gateway_ms": secured,
        "hub_verify_ms": hub_verify,
        "gateway_added_overhead_mean_ms": gateway_overhead,
        "gateway_p99_within_budget": secured["p99_ms"] < INTER_PACKET_BUDGET_MS,
        "max_sustainable_pps_gateway": int(1000.0 / secured["mean_ms"]) if secured["mean_ms"] else 0,
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  baseline pass-through : mean={baseline['mean_ms']}ms p99={baseline['p99_ms']}ms")
    print(f"  secured gateway       : mean={secured['mean_ms']}ms p99={secured['p99_ms']}ms")
    print(f"  hub verify            : mean={hub_verify['mean_ms']}ms p99={hub_verify['p99_ms']}ms")
    print(f"  added gateway overhead: {gateway_overhead}ms (budget {INTER_PACKET_BUDGET_MS:.1f}ms/packet)")
    print(f"  max sustainable rate  : {report['max_sustainable_pps_gateway']} packets/s")
    print(f"saved to {args.output}")


if __name__ == "__main__":
    main()
