"""ATK3: tampering via an on-path MitM relay (full and partial mutation)."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import ssl
import subprocess
import sys
import time

import websockets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks._logreader import file_offset, read_after_offset

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAMPERED_COMMANDS = ["confirm", "select_B", "move_right", "select_A"]


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _terminate(proc: subprocess.Popen, name: str, grace: float = 2.0) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        print(f"  [orchestrator] {name} did not exit; killing.")
        proc.kill()
        proc.wait()


async def _device_feed(
    uri: str, ssl_ctx, max_packets: int, device_id: str = "bci-device-001",
) -> int:
    sent = 0
    try:
        async with websockets.connect(uri, ssl=ssl_ctx) as ws:
            for seq in range(max_packets):
                await ws.send(json.dumps({
                    "device_id": device_id,
                    "timestamp": int(time.time() * 1000),
                    "seq": seq,
                    "channels": [3.0 + seq * 0.01] * 8,
                    "command": "idle",
                }))
                sent += 1
                await asyncio.sleep(0.002)
    except Exception as e:
        print(f"  [device_feed] stopped: {e}")
    return sent


def _feed_ssl(cert: str, key: str, ca_cert: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_cert)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _run_one_secured(
    variant: str,
    mutation_rate: float,
    gateway_host: str,
    gateway_outbound_port: int,
    gateway_inbound_uri: str,
    feed_ssl: ssl.SSLContext,
    mitm_listen_port: int,
    sidecar_dashboard_port: int,
    hmac_key: str,
    max_packets: int,
    sidecar_log_path: str,
    mitm_stdout_path: str,
) -> dict:
    py = sys.executable
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    os.makedirs(os.path.dirname(sidecar_log_path) or ".", exist_ok=True)

    # relay emits counters once a second, so the last logged snapshot survives a hard kill
    mitm_stdout = open(mitm_stdout_path, "w", encoding="utf-8")
    mitm = subprocess.Popen(
        [
            py, "-m", "attacks.mitm_proxy",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(mitm_listen_port),
            "--gateway-host", gateway_host,
            "--gateway-port", str(gateway_outbound_port),
            "--mutation-rate", str(mutation_rate),
        ],
        cwd=REPO_ROOT, stdout=mitm_stdout, stderr=subprocess.STDOUT, env=env,
    )
    print(f"  [{variant}] mitm_proxy pid={mitm.pid} on :{mitm_listen_port} rate={mutation_rate}")
    if not _wait_for_port("127.0.0.1", mitm_listen_port, timeout=5.0):
        _terminate(mitm, "mitm_proxy")
        mitm_stdout.close()
        raise RuntimeError("mitm_proxy did not bind in time")

    sidecar_log = open(sidecar_log_path, "w", encoding="utf-8")
    sidecar = subprocess.Popen(
        [
            py, "-m", "hub.main",
            "--mode", "secured",
            "--gateway-host", "127.0.0.1",
            "--gateway-port", str(mitm_listen_port),
            "--dashboard-port", str(sidecar_dashboard_port),
            "--hmac-key", hmac_key,
        ],
        cwd=REPO_ROOT, stdout=sidecar_log, stderr=subprocess.STDOUT, env=env,
    )
    print(f"  [{variant}] sidecar hub pid={sidecar.pid} dash=:{sidecar_dashboard_port}")
    if not _wait_for_port("127.0.0.1", sidecar_dashboard_port, timeout=5.0):
        _terminate(sidecar, "sidecar hub")
        _terminate(mitm, "mitm_proxy")
        sidecar_log.close()
        mitm_stdout.close()
        raise RuntimeError("sidecar hub did not bind in time")

    await asyncio.sleep(1.5)  # let the sidecar hub connect upstream to the relay
    pre_window_offset = file_offset(sidecar_log_path)

    print(f"  [{variant}] feeding {max_packets} packets through the gateway")
    window_start = int(time.time() * 1000)
    feed_sent = await _device_feed(gateway_inbound_uri, feed_ssl, max_packets)
    await asyncio.sleep(2.5)  # let in-flight packets reach the sidecar hub
    window_end = int(time.time() * 1000)

    _terminate(mitm, "mitm_proxy")
    _terminate(sidecar, "sidecar hub")
    sidecar_log.close()
    mitm_stdout.close()

    mitm_counters: dict = {}
    try:
        with open(mitm_stdout_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    parsed = json.loads(line)
                    if "mitm_counters" in parsed:
                        mitm_counters = parsed["mitm_counters"]
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass

    sidecar_text = read_after_offset(sidecar_log_path, pre_window_offset)
    hmac_mismatches = sum(1 for ln in sidecar_text.splitlines() if "HMAC mismatch" in ln)

    mutated = mitm_counters.get("mutated", 0)
    untouched = mitm_counters.get("untouched", 0)
    blocked = mutated > 0 and hmac_mismatches >= mutated

    return {
        "variant": variant,
        "mutation_rate": mutation_rate,
        "feed_packets_sent": feed_sent,
        "attacker_view": {
            "forwarded_total": mitm_counters.get("forwarded_total", 0),
            "data_packets_seen": mitm_counters.get("data_packets_seen", 0),
            "mutated": mutated,
            "untouched": untouched,
            "relay_errors": mitm_counters.get("relay_errors", 0),
        },
        "defender_view": {
            "sidecar_hub_log": sidecar_log_path,
            "hmac_mismatches_dropped": hmac_mismatches,
            "window_ms": [window_start, window_end],
        },
        "blocked": blocked,
    }


async def _run_baseline(host: str, port: int, num_packets: int) -> dict:
    uri = f"ws://{host}:{port}"
    sent = 0
    print(f"  [forged_injection] injecting {num_packets} forged packets at {uri}")
    try:
        async with websockets.connect(uri) as ws:
            for i in range(num_packets):
                await ws.send(json.dumps({
                    "device_id": "bci-device-001",
                    "timestamp": int(time.time() * 1000),
                    "seq": i,
                    "channels": [5.0 + i * 0.1] * 8,
                    "command": TAMPERED_COMMANDS[i % len(TAMPERED_COMMANDS)],
                }))
                sent += 1
                await asyncio.sleep(0.05)
    except Exception as e:
        print(f"  [forged_injection] connection error: {e}")

    return {
        "attack": "ATK3_tamper",
        "attacker_model": "forged-packet injection at the undefended hub (baseline)",
        "blocked_by": "F2 (HMAC verification at the hub)",
        "params": {"num_packets": num_packets},
        "variants": {
            "forged_injection": {
                "variant": "forged_injection",
                "attacker_view": {"packets_sent": sent},
                "defender_view": {"skipped": True, "note": "baseline pipeline has no HMAC verification"},
                "blocked": False,
            }
        },
        "success_criterion_met": False,
    }


async def run_tamper(
    host: str,
    port: int,
    num_packets: int,
    use_hmac: bool,
    hmac_key: str,
    *,
    gateway_host: str = "127.0.0.1",
    gateway_port: int = 9001,
    gateway_inbound_port: int = 9000,
    cert: str = "certs/devices/device-001.crt",
    key: str = "certs/devices/device-001.key",
    ca_cert: str = "certs/ca/testbed-ca.crt",
    mitm_listen_port: int = 9101,
    sidecar_dashboard_port: int = 8003,
    feed_packets: int = 800,
    results_dir: str = "evaluation/results",
) -> dict:
    if not use_hmac:
        return await _run_baseline(host, port, num_packets)

    feed_ssl = _feed_ssl(cert, key, ca_cert)
    gateway_inbound_uri = f"wss://{gateway_host}:{gateway_inbound_port}"

    variants: dict = {}
    for name, rate in (("full_mutation", 1.0), ("partial_mutation", 0.1)):
        variants[name] = await _run_one_secured(
            variant=name,
            mutation_rate=rate,
            gateway_host=gateway_host,
            gateway_outbound_port=gateway_port,
            gateway_inbound_uri=gateway_inbound_uri,
            feed_ssl=feed_ssl,
            mitm_listen_port=mitm_listen_port,
            sidecar_dashboard_port=sidecar_dashboard_port,
            hmac_key=hmac_key,
            max_packets=feed_packets,
            sidecar_log_path=f"{results_dir}/atk3_sidecar_{name}.log",
            mitm_stdout_path=f"{results_dir}/atk3_mitm_{name}.log",
        )
        print(f"    {name}: mutated={variants[name]['attacker_view']['mutated']} "
              f"hmac_mismatches={variants[name]['defender_view']['hmac_mismatches_dropped']} "
              f"blocked={variants[name]['blocked']}")

    return {
        "attack": "ATK3_tamper",
        "attacker_model": "on-path MitM relay between the gateway and the hub",
        "blocked_by": "F2 (HMAC-SHA256 verification at the hub)",
        "params": {"feed_packets": feed_packets},
        "variants": variants,
        "defender_view": {
            "note": "each mutated packet fails HMAC verification at the sidecar hub; "
                    "untouched packets pass, so detection is precise",
        },
        "success_criterion_met": all(v["blocked"] for v in variants.values()),
    }


def main():
    parser = argparse.ArgumentParser(description="ATK3: tampering / on-path MitM")
    parser.add_argument("--baseline", action="store_true",
                        help="Forged-packet injection against an undefended hub")
    parser.add_argument("--host", default="127.0.0.1", help="Hub host (baseline mode)")
    parser.add_argument("--port", type=int, default=8001, help="Hub port (baseline mode)")
    parser.add_argument("--gateway-host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=9001)
    parser.add_argument("--gateway-inbound-port", type=int, default=9000)
    parser.add_argument("--cert", default="certs/devices/device-001.crt")
    parser.add_argument("--key", default="certs/devices/device-001.key")
    parser.add_argument("--ca-cert", default="certs/ca/testbed-ca.crt")
    parser.add_argument("--mitm-listen-port", type=int, default=9101)
    parser.add_argument("--sidecar-dashboard-port", type=int, default=8003)
    parser.add_argument("--feed-packets", type=int, default=800,
                        help="Legitimate packets fed through the gateway per variant")
    parser.add_argument("--num-packets", type=int, default=20,
                        help="Forged packet count (baseline mode only)")
    parser.add_argument("--hmac-key", default="super-secret-hmac-key-for-prototype")
    parser.add_argument("--results-dir", default="evaluation/results")
    args = parser.parse_args()

    print("ATK3 tamper (on-path MitM)" + (" (baseline mode)" if args.baseline else ""))
    results = asyncio.run(run_tamper(
        host=args.host, port=args.port, num_packets=args.num_packets,
        use_hmac=not args.baseline, hmac_key=args.hmac_key,
        gateway_host=args.gateway_host, gateway_port=args.gateway_port,
        gateway_inbound_port=args.gateway_inbound_port,
        cert=args.cert, key=args.key, ca_cert=args.ca_cert,
        mitm_listen_port=args.mitm_listen_port,
        sidecar_dashboard_port=args.sidecar_dashboard_port,
        feed_packets=args.feed_packets, results_dir=args.results_dir,
    ))
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    main()
