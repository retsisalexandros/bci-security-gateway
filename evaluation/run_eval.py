"""Evaluation orchestrator: pipeline, normal-traffic phase, attack suite,
overhead benchmark, results collection. Usage: --mode {baseline,secured,both}."""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from attacks._logreader import read_gateway_events, events_in_window, count_events

PY = sys.executable
RESULTS = os.path.join(REPO_ROOT, "evaluation", "results")
GATEWAY_LOG = os.path.join(REPO_ROOT, "gateway_events.log")
NORMAL_SECONDS = 10


def _wait_for_port(host: str, port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _spawn(cmd: list[str], log_path: str | None = None) -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    out = open(log_path, "w", encoding="utf-8") if log_path else subprocess.DEVNULL
    return subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=out, stderr=subprocess.STDOUT, env=env)


def _terminate(proc: subprocess.Popen, name: str) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    print(f"  stopped {name}")


def _normal_traffic_phase(mode: str, sim_cmd: list[str]) -> dict:
    print(f"[phase A] normal traffic for {NORMAL_SECONDS}s (false-positive check)")
    start_ms = int(time.time() * 1000)
    sim = _spawn(sim_cmd, os.path.join(RESULTS, f"simulator_{mode}.log"))
    time.sleep(NORMAL_SECONDS)
    _terminate(sim, "simulator")
    end_ms = int(time.time() * 1000)
    time.sleep(0.5)

    if mode == "baseline":
        return {
            "mode": mode,
            "note": "baseline pipeline has no gateway; no enforcement to measure",
            "window_ms": [start_ms, end_ms],
        }

    events = read_gateway_events(GATEWAY_LOG)
    scoped = events_in_window(events, start_ms - 500, end_ms + 1500)
    forwarded = count_events(scoped, "packet_forwarded", device_id="bci-device-001")
    rejected = count_events(scoped, "packet_rejected", device_id="bci-device-001")
    replay = count_events(scoped, "replay_rejected", device_id="bci-device-001")
    rate_limited = count_events(scoped, "rate_limited", device_id="bci-device-001")
    anomalies = count_events(scoped, "anomaly_detected", device_id="bci-device-001")
    auth_fail = count_events(scoped, "auth_failure")
    false_rejections = rejected + replay + rate_limited
    total = forwarded + false_rejections
    fp_rate = round(false_rejections / total, 6) if total else 0.0
    summary = {
        "mode": mode,
        "window_ms": [start_ms, end_ms],
        "legitimate_packets_forwarded": forwarded,
        "false_rejections": false_rejections,
        "false_rate_limited": rate_limited,
        "false_anomaly_alerts": anomalies,
        "auth_failures": auth_fail,
        "false_positive_rate": fp_rate,
    }
    print(f"  forwarded={forwarded} false_rejections={false_rejections} "
          f"false_anomaly_alerts={anomalies} fp_rate={fp_rate}")
    with open(os.path.join(RESULTS, f"normal_operation_{mode}.json"), "w") as f:
        json.dump(summary, f, indent=2)
    return summary


def run_secured() -> None:
    print("\n=== SECURED EVALUATION ===")
    open(GATEWAY_LOG, "w").close()
    procs: dict = {}
    try:
        print("[1] gateway on 9000 (mTLS) / 9001 (hub)")
        procs["gateway"] = _spawn(
            [PY, "-m", "gateway.main", "--config", "config.json"],
            os.path.join(RESULTS, "gateway_secured.log"),
        )
        if not _wait_for_port("127.0.0.1", 9000) or not _wait_for_port("127.0.0.1", 9001):
            raise RuntimeError("gateway did not start")

        print("[2] hub (secured) dashboard on 8002")
        procs["hub"] = _spawn(
            [PY, "-m", "hub.main", "--mode", "secured", "--gateway-host", "127.0.0.1",
             "--gateway-port", "9001", "--dashboard-port", "8002", "--config", "config.json"],
            os.path.join(RESULTS, "hub_secured.log"),
        )
        if not _wait_for_port("127.0.0.1", 8002):
            raise RuntimeError("hub did not start")
        time.sleep(1.0)

        _normal_traffic_phase("secured", [
            PY, "-m", "simulator.main", "--host", "127.0.0.1", "--port", "9000",
            "--device-id", "bci-device-001",
            "--cert", "certs/devices/device-001.crt",
            "--key", "certs/devices/device-001.key",
            "--ca-cert", "certs/ca/testbed-ca.crt",
        ])

        print("[phase B] attack suite")
        subprocess.run(
            [PY, "attacks/run_all.py", "--host", "127.0.0.1",
             "--gateway-port", "9000", "--gateway-outbound-port", "9001",
             "--gateway-log", "gateway_events.log",
             "--output", "evaluation/results/attack_results_secured.json"],
            cwd=REPO_ROOT, check=False,
        )
    finally:
        for name, proc in procs.items():
            _terminate(proc, name)

    print("[phase C] per-packet overhead benchmark")
    subprocess.run([PY, "evaluation/measure_overhead.py"], cwd=REPO_ROOT, check=False)


def run_baseline() -> None:
    print("\n=== BASELINE EVALUATION ===")
    procs: dict = {}
    try:
        print("[1] hub (baseline) upstream 8001 / dashboard 8002")
        procs["hub"] = _spawn(
            [PY, "-m", "hub.main", "--mode", "baseline", "--port", "8001",
             "--dashboard-port", "8002"],
            os.path.join(RESULTS, "hub_baseline.log"),
        )
        if not _wait_for_port("127.0.0.1", 8001):
            raise RuntimeError("hub did not start")
        time.sleep(1.0)

        _normal_traffic_phase("baseline", [
            PY, "-m", "simulator.main", "--no-tls", "--host", "127.0.0.1",
            "--port", "8001", "--device-id", "bci-device-001",
        ])

        print("[phase B] attack suite")
        subprocess.run(
            [PY, "attacks/run_all.py", "--baseline", "--host", "127.0.0.1",
             "--hub-port", "8001",
             "--output", "evaluation/results/attack_results_baseline.json"],
            cwd=REPO_ROOT, check=False,
        )
    finally:
        for name, proc in procs.items():
            _terminate(proc, name)


def main():
    parser = argparse.ArgumentParser(description="BCI evaluation orchestrator")
    parser.add_argument("--mode", choices=["baseline", "secured", "both"], default="both")
    args = parser.parse_args()

    os.makedirs(RESULTS, exist_ok=True)

    if args.mode in ("baseline", "both"):
        run_baseline()
    if args.mode in ("secured", "both"):
        run_secured()

    print("\n[collect] evaluation summary")
    subprocess.run([PY, "evaluation/collect_metrics.py"], cwd=REPO_ROOT, check=False)
    print("\nevaluation complete; see evaluation/results/")


if __name__ == "__main__":
    main()
