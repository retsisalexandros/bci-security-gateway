"""F4 studies: anomaly detector sensitivity sweep and extended false-positive check."""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gateway.anomaly import BehaviouralDetector
from simulator.signal_generator import SignalGenerator, FileSignalGenerator

RESULTS = os.path.join(ROOT, "evaluation", "results")
DEVICE = "bci-device-001"
DEFAULT_EEG = os.path.join(ROOT, "datasets", "eeg+eye+state", "EEG Eye State.arff")


def make_generator(seed: int | None = None) -> SignalGenerator:
    gen = SignalGenerator(num_channels=8, sampling_rate=250)
    if seed is not None:
        rng = np.random.default_rng(seed)
        gen.phase_offsets = rng.uniform(0, 2 * np.pi, size=(8, 5))
        gen.amplitudes = rng.uniform(low=[20, 10, 15, 5, 3], high=[40, 20, 30, 15, 7], size=(8, 5))
        gen.frequencies = rng.uniform(low=[0.5, 4, 8, 13, 0], high=[4, 8, 13, 30, 0], size=(8, 5))
    return gen


def sensitivity_sweep() -> list[dict]:
    rows = []
    for learn_samples in (100, 300, 1000):
        for z_threshold in (3.0, 4.5, 6.0, 8.0):
            detector = BehaviouralDetector(
                learn_samples=learn_samples, z_threshold=z_threshold, channel_bound=300.0
            )
            gen = make_generator(seed=42)
            for _ in range(learn_samples):
                detector.observe(DEVICE, {"channels": gen.next_sample()})
            state = detector._state[DEVICE]
            mean, std = state["mean"], state["std"]

            fa_sample, false_alarms = 2000, 0
            for _ in range(fa_sample):
                if detector.observe(DEVICE, {"channels": gen.next_sample()}) is not None:
                    false_alarms += 1

            jitter = np.random.default_rng(7)
            detection = {}
            for k in (2, 3, 4, 5, 6, 8):
                trials, by_z, by_bound = 300, 0, 0
                for _ in range(trials):
                    channels = [float(mean + k * std + jitter.normal(0, std)) for _ in range(8)]
                    result = detector.observe(DEVICE, {"channels": channels})
                    if result is not None:
                        if result.startswith("channel_anomaly"):
                            by_z += 1
                        elif result.startswith("channel_out"):
                            by_bound += 1
                detection[k] = {
                    "total": round((by_z + by_bound) / trials, 3),
                    "by_zscore": round(by_z / trials, 3),
                    "by_hard_bound": round(by_bound / trials, 3),
                }

            rows.append({
                "learn_samples": learn_samples,
                "z_threshold": z_threshold,
                "learned_mean": round(mean, 3),
                "learned_std": round(std, 3),
                "false_alarm_rate": round(false_alarms / fa_sample, 5),
                "false_alarms": false_alarms,
                "fa_sample": fa_sample,
                "detection_by_deviation_sigma": detection,
            })
    return rows


def _false_positive_run(source: str, generator, test_packets: int) -> dict:
    detector = BehaviouralDetector(learn_samples=300, z_threshold=6.0, channel_bound=300.0)
    for _ in range(300):
        detector.observe(DEVICE, {"channels": generator.next_sample()})
    std = detector._state[DEVICE]["std"]
    alerts = 0
    for _ in range(test_packets):
        if detector.observe(DEVICE, {"channels": generator.next_sample()}) is not None:
            alerts += 1
    return {
        "source": source,
        "learned_std": round(std, 3),
        "test_packets": test_packets,
        "false_anomaly_alerts": alerts,
        "fp_rate": round(alerts / test_packets, 6),
    }


def extended_false_positives(eeg_file: str, test_packets: int = 2500) -> list[dict]:
    rows = [
        _false_positive_run(f"synthetic_seed_{seed}", make_generator(seed=seed), test_packets)
        for seed in (1, 2, 3, 4, 5)
    ]
    if os.path.exists(eeg_file):
        rows.append(_false_positive_run(
            "recorded_EEG_UCI_EyeState", FileSignalGenerator(eeg_file, num_channels=8), test_packets
        ))
    else:
        print(f"  recorded EEG source skipped, file not found: {eeg_file}")
        print("  download the UCI EEG Eye State dataset to include it:")
        print("  https://doi.org/10.24432/C57G7J")
    return rows


def main():
    parser = argparse.ArgumentParser(description="F4 sensitivity and false-positive studies")
    parser.add_argument("--eeg-file", default=DEFAULT_EEG,
                        help="Recorded EEG file for the extended false-positive check")
    parser.add_argument("--test-packets", type=int, default=2500,
                        help="Legitimate packets per source in the false-positive check")
    args = parser.parse_args()

    os.makedirs(RESULTS, exist_ok=True)

    print("F4 sensitivity sweep")
    sweep = sensitivity_sweep()
    with open(os.path.join(RESULTS, "sensitivity_atk6.json"), "w") as f:
        json.dump({
            "config_default": {"learn_samples": 300, "z_threshold": 6.0, "channel_bound": 300.0},
            "sweep": sweep,
        }, f, indent=2)

    print("extended false-positive check")
    runs = extended_false_positives(args.eeg_file, args.test_packets)
    with open(os.path.join(RESULTS, "false_positive_extended.json"), "w") as f:
        json.dump({
            "config": {"learn_samples": 300, "z_threshold": 6.0, "channel_bound": 300.0, "max_pps": 400},
            "note_rate_limiter": "At 250 Hz the device is well below the 400 pps cap, so no legitimate packet is rate-limited by construction; this study stresses the anomaly detector.",
            "runs": runs,
        }, f, indent=2)

    print(f"\n{'learn':>6} {'z_thr':>6} {'std':>7} {'FA':>8} | " + " ".join(f"{k}s".rjust(6) for k in (2, 3, 4, 5, 6, 8)))
    for row in sweep:
        d = row["detection_by_deviation_sigma"]
        print(f"{row['learn_samples']:>6} {row['z_threshold']:>6} {row['learned_std']:>7} "
              f"{row['false_alarm_rate']:>8} | " + " ".join(f"{d[k]['total']:>6}" for k in (2, 3, 4, 5, 6, 8)))

    print(f"\n{'source':>28} {'learned_std':>12} {'test_pkts':>10} {'false_alerts':>13} {'fp_rate':>9}")
    total_alerts = total_packets = 0
    for row in runs:
        total_alerts += row["false_anomaly_alerts"]
        total_packets += row["test_packets"]
        print(f"{row['source']:>28} {row['learned_std']:>12} {row['test_packets']:>10} "
              f"{row['false_anomaly_alerts']:>13} {row['fp_rate']:>9}")
    print(f"{'TOTAL':>28} {'':>12} {total_packets:>10} {total_alerts:>13} "
          f"{round(total_alerts / total_packets, 6):>9}")

    print("\nsaved to evaluation/results/{sensitivity_atk6,false_positive_extended}.json")


if __name__ == "__main__":
    main()
