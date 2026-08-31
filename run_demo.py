from __future__ import annotations

import argparse
import asyncio
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
HMAC_KEY = "super-secret-hmac-key-for-prototype"
DASH_URL = "http://localhost:5173"
MITM_PORT = 9101
TAMPER_FLAG = os.path.join(ROOT, ".tamper_active")

if sys.platform == "win32":
    _libbin = os.path.join(sys.prefix, "Library", "bin")
    if os.path.isdir(_libbin):
        os.environ["PATH"] = _libbin + os.pathsep + os.environ.get("PATH", "")

sys.path.insert(0, ROOT)
from attacks.spoof_device import run_spoof
from attacks.replay_attack import run_replay
from attacks.unauth_access import run_unauth
from attacks.fuzz_input import run_fuzz

procs: list[subprocess.Popen] = []


def cleanup(*_):
    print("\nshutting down ...")
    if os.path.exists(TAMPER_FLAG):
        try:
            os.remove(TAMPER_FLAG)
        except OSError:
            pass
    for p in reversed(procs):
        try:
            p.terminate()
        except OSError:
            pass
    for p in reversed(procs):
        try:
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except OSError:
                pass
    sys.exit(0)


def spawn(cmd, shell=False, cwd=ROOT):
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    p = subprocess.Popen(cmd, cwd=cwd, shell=shell, env=env)
    procs.append(p)
    return p


def wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def banner(text):
    line = "=" * 68
    print(f"\n{line}\n  {text}\n{line}")


def gate(manual, msg):
    if manual:
        input(f"\n>>> {msg} (press Enter) ")
    else:
        print(f"\n>>> {msg}")


def countdown(seconds, msg):
    for s in range(seconds, 0, -1):
        print(f"  {msg} in {s:2d}s ...", end="\r", flush=True)
        time.sleep(1)
    print(" " * 60, end="\r")


EEG_FILE = None

def sim_cmd():
    cmd = [
        PY, "-m", "simulator.main", "--host", "127.0.0.1", "--port", "9000",
        "--device-id", "bci-device-001",
        "--cert", "certs/devices/device-001.crt",
        "--key", "certs/devices/device-001.key",
        "--ca-cert", "certs/ca/testbed-ca.crt",
    ]
    if EEG_FILE:
        cmd += ["--eeg-file", EEG_FILE]
    return cmd


async def attack_phase():
    host, gw = "127.0.0.1", 9000

    banner("ATK1  device spoofing  (control F1, mTLS)")
    print("  Rejected during the TLS handshake, below the gateway's application")
    print("  logger, so this one shows in the terminal but not on the dashboard.")
    r = await run_spoof(host, gw, attempts=5)
    print(f"  result: blocked={r['success_criterion_met']}")
    await asyncio.sleep(3)

    banner("ATK4  unauthorised access  (control F1, allowlist)  ->  dashboard F1")
    r = await run_unauth(host, gw, attempts=10)
    print(f"  result: blocked={r['success_criterion_met']}  (watch the F1 row climb)")
    await asyncio.sleep(4)

    banner("ATK2  replay  (control F3, anti-replay)  ->  dashboard F3")
    r = await run_replay(host=host, port=gw,
                         cert="certs/devices/device-001.crt",
                         key="certs/devices/device-001.key",
                         ca_cert="certs/ca/testbed-ca.crt",
                         capture_count=20, delay=7.0, baseline=False,
                         gateway_log="gateway_events.log")
    print(f"  result: blocked={r['success_criterion_met']}  (watch the F3 row climb)")
    await asyncio.sleep(4)

    banner("ATK5  malformed-input fuzzing  (input validation)  ->  dashboard IV")
    r = await run_fuzz(host, gw, gateway_log="gateway_events.log")
    print(f"  result: blocked={r['success_criterion_met']}  (watch the IV row climb)")
    await asyncio.sleep(4)

    banner("ATK3  tampering / on-path MitM  (control F2, HMAC)  ->  dashboard F2")
    print("  Activating the on-path MitM on the live gateway->hub link: it flips the")
    print("  command field, the hub's HMAC check fails, frames are dropped and logged.")
    open(TAMPER_FLAG, "w").close()
    await asyncio.sleep(5)
    if os.path.exists(TAMPER_FLAG):
        os.remove(TAMPER_FLAG)
    print("  tampering stopped  (watch the F2 row climb; EEG resumes as frames pass again)")


def main():
    parser = argparse.ArgumentParser(description="BCI live demo launcher")
    parser.add_argument("--manual", action="store_true",
                        help="Pause for Enter between phases instead of auto-pacing")
    parser.add_argument("--showcase", action="store_true",
                        help="Bring up the pipeline, dashboard and live device, then idle "
                             "(no auto-attacks). Use for a presentation you drive yourself.")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="Do not start the dashboard dev server")
    parser.add_argument("--normal-seconds", type=int, default=15)
    parser.add_argument("--eeg-file", default=None,
                        help="Stream a recorded EEG file (CSV) through the pipeline")
    parser.add_argument("--pick-eeg", action="store_true",
                        help="Open a file dialog to choose a recorded EEG file")
    args = parser.parse_args()

    global EEG_FILE
    EEG_FILE = args.eeg_file
    if args.pick_eeg and not EEG_FILE:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk(); root.withdraw()
            EEG_FILE = filedialog.askopenfilename(
                title="Select a recorded EEG file (CSV)",
                filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
            ) or None
            root.destroy()
        except Exception as e:
            print(f"could not open file dialog ({e}); pass --eeg-file <path> instead")
    if EEG_FILE:
        print(f"  streaming recorded EEG: {EEG_FILE}")

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    open(os.path.join(ROOT, "gateway_events.log"), "w").close()

    banner("BCI Security Gateway  ::  live demo")
    print("  Bringing up the secured pipeline (gateway, hub, dashboard).")

    if os.path.exists(TAMPER_FLAG):
        os.remove(TAMPER_FLAG)

    spawn([PY, "-m", "gateway.main", "--config", "config.json"])
    if not (wait_port(9000) and wait_port(9001)):
        print("gateway did not start; see its window/output."); cleanup()
    print("  gateway up on 9000 (mTLS) / 9001 (hub)")

    spawn([PY, "-m", "attacks.mitm_proxy",
           "--listen-host", "127.0.0.1", "--listen-port", str(MITM_PORT),
           "--gateway-host", "127.0.0.1", "--gateway-port", "9001",
           "--mutation-rate", "1.0", "--mutate-flag-file", TAMPER_FLAG])
    if not wait_port(MITM_PORT):
        print("mitm relay did not start."); cleanup()
    print(f"  mitm relay up on {MITM_PORT} (passthrough until tampering is triggered)")

    spawn([PY, "-m", "hub.main", "--mode", "secured",
           "--gateway-host", "127.0.0.1", "--gateway-port", str(MITM_PORT),
           "--dashboard-port", "8002", "--config", "config.json"])
    if not wait_port(8002):
        print("hub did not start."); cleanup()
    print("  hub up (behind mitm), dashboard feed on 8002")

    if not args.no_dashboard:
        spawn("npm run dev", shell=True, cwd=os.path.join(ROOT, "dashboard"))
        print(f"  dashboard dev server starting -> {DASH_URL}")

    if args.showcase:
        spawn(sim_cmd())
        banner("SHOWCASE  ::  live pipeline up")
        print(f"  Open {DASH_URL} in your browser. Legitimate device is streaming:")
        print("  EEG animates, metrics are green, Threat Monitor shows 0 threats.")
        print("  To launch attacks while presenting (F1/F3/IV), run or double-click:")
        print("      run_attacks.bat   (or: python attacks/run_all.py --host 127.0.0.1 --gateway-port 9000)")
        print("  To demo F2 (integrity) on the live link, run or double-click:")
        print("      tamper.bat")
        print("  Ctrl+C here stops everything.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            cleanup()
        return

    gate(args.manual, f"Open {DASH_URL} in your browser")
    if not args.manual:
        countdown(20, "normal operation begins")

    banner("PHASE 1  normal operation")
    print("  Legitimate device streaming. EEG animates, metrics are green, 0 threats.")
    sim = spawn(sim_cmd())
    time.sleep(args.normal_seconds)
    sim.terminate()
    try:
        sim.wait(timeout=3)
    except Exception:
        sim.kill()
    procs.remove(sim)
    time.sleep(1)

    gate(args.manual, "Launch the attacks")
    if not args.manual:
        countdown(5, "attacks begin")

    banner("PHASE 2  attacks  ::  watch the Threat Monitor")
    asyncio.run(attack_phase())

    banner("PHASE 3  recovery")
    print("  Attacks done. Resuming legitimate traffic; the pipeline keeps serving.")
    spawn(SIM_CMD)

    print("\n  Demo complete. Dashboard stays live. Press Ctrl+C to stop everything.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
