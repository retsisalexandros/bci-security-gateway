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

print("secured pipeline\n")

print("[1] gateway on 9000/9001")
processes.append(subprocess.Popen(
    [PYTHON, "-m", "gateway.main", "--config", "config.json"],
    cwd=PROJECT,
))
time.sleep(2)

print("[2] hub (secured) on 9001/8002")
processes.append(subprocess.Popen(
    [PYTHON, "-m", "hub.main", "--mode", "secured", "--port", "9001", "--dashboard-port", "8002", "--config", "config.json"],
    cwd=PROJECT,
))
time.sleep(2)

print("[3] simulator (mtls) -> gateway:9000")
processes.append(subprocess.Popen(
    [PYTHON, "-m", "simulator.main",
     "--host", "localhost", "--port", "9000",
     "--cert", "certs/devices/device-001.crt",
     "--key", "certs/devices/device-001.key",
     "--ca-cert", "certs/ca/testbed-ca.crt"],
    cwd=PROJECT,
))
time.sleep(1)

print("[4] dashboard dev server")
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
