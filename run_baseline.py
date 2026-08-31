import subprocess
import sys
import os
import time
import signal

PROJECT = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable

processes = []

def cleanup(*_):
    print("\nshutting down")
    for p in processes:
        try:
            p.terminate()
        except OSError:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

print("baseline pipeline\n")

print("[1] hub (baseline) on 8001/8002")
processes.append(subprocess.Popen(
    [PYTHON, "-m", "hub.main", "--mode", "baseline", "--port", "8001", "--dashboard-port", "8002"],
    cwd=PROJECT,
))
time.sleep(2)

print("[2] simulator (no tls) -> hub:8001")
processes.append(subprocess.Popen(
    [PYTHON, "-m", "simulator.main", "--no-tls", "--host", "localhost", "--port", "8001"],
    cwd=PROJECT,
))
time.sleep(1)

print("[3] dashboard dev server")
processes.append(subprocess.Popen(
    ["npm", "run", "dev"],
    cwd=os.path.join(PROJECT, "dashboard"),
    shell=True,
))

print("\nall started")
print("open http://localhost:5173")
print("ctrl+c to stop\n")

try:
    while True:
        time.sleep(1)
        for p in processes:
            if p.poll() is not None:
                print(f"process {p.args} exited with code {p.returncode}")
except KeyboardInterrupt:
    cleanup()
