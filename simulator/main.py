import argparse
import asyncio
import json
import logging
import sys

from .client import run_client


def _raise_timer_resolution():
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)


def main():
    parser = argparse.ArgumentParser(description="BCI Device Simulator")
    parser.add_argument("--device-id", default="bci-device-001")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--sampling-rate", type=int, default=250)
    parser.add_argument("--cert", default=None, help="Client certificate path")
    parser.add_argument("--key", default=None, help="Client key path")
    parser.add_argument("--ca-cert", default=None, help="CA certificate path")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS (baseline mode)")
    parser.add_argument("--config", default=None, help="Path to config.json")
    parser.add_argument("--eeg-file", default=None,
                        help="Stream a recorded EEG file (CSV) instead of synthetic signal")
    parser.add_argument("--pick-eeg", action="store_true",
                        help="Open a file dialog to choose a recorded EEG file")

    args = parser.parse_args()

    if args.pick_eeg and not args.eeg_file:
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk(); root.withdraw()
            args.eeg_file = filedialog.askopenfilename(
                title="Select a recorded EEG file (CSV)",
                filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
            )
            root.destroy()
        except Exception as e:
            print(f"could not open file dialog ({e}); pass --eeg-file <path> instead")
        if not args.eeg_file:
            print("no file selected; using synthetic signal")

    if args.config:
        with open(args.config) as f:
            cfg = json.load(f).get("simulator", {})
        if args.device_id == "bci-device-001" and "device_id" in cfg:
            args.device_id = cfg["device_id"]
        if args.host == "localhost" and "gateway_host" in cfg:
            args.host = cfg["gateway_host"]
        if args.port == 9000 and "gateway_port" in cfg:
            args.port = cfg["gateway_port"]
        if args.cert is None and "cert" in cfg:
            args.cert = cfg["cert"]
        if args.key is None and "key" in cfg:
            args.key = cfg["key"]
        if args.ca_cert is None and "ca_cert" in cfg:
            args.ca_cert = cfg["ca_cert"]

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    _raise_timer_resolution()

    asyncio.run(
        run_client(
            device_id=args.device_id,
            host=args.host,
            port=args.port,
            sampling_rate=args.sampling_rate,
            cert=args.cert,
            key=args.key,
            ca_cert=args.ca_cert,
            no_tls=args.no_tls,
            eeg_file=args.eeg_file,
        )
    )


if __name__ == "__main__":
    main()
