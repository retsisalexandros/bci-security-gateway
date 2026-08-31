"""Aggregates attack results, event log, overhead and normal-operation into one summary."""
from __future__ import annotations

import json
import argparse
import os

EVENT_TYPES = [
    "auth_success", "auth_failure", "packet_forwarded",
    "replay_rejected", "packet_rejected", "rate_limited", "anomaly_detected",
]
ATTACKS = ["ATK1_spoof", "ATK2_replay", "ATK3_tamper", "ATK4_unauth", "ATK5_fuzz", "ATK6_abnormal"]


def parse_event_log(log_path: str) -> dict:
    counts = {t: 0 for t in EVENT_TYPES}
    counts["total_events"] = 0
    if not os.path.exists(log_path):
        print(f"  warning: log file not found: {log_path}")
        return counts
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = entry.get("event_type", "")
            if et in counts:
                counts[et] += 1
            counts["total_events"] += 1
    return counts


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        print(f"  note: not found: {path}")
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _variant_flags(attack: dict) -> dict:
    return {
        name: bool(v.get("blocked"))
        for name, v in attack.get("variants", {}).items()
    }


def summarise_attack(name: str, baseline: dict, secured: dict) -> dict:
    b = baseline.get(name, {})
    s = secured.get(name, {})
    entry: dict = {"blocked_by": s.get("blocked_by") or b.get("blocked_by", "?")}

    if b.get("skipped"):
        entry["baseline"] = f"skipped ({b.get('reason', '')})"
    else:
        entry["baseline_attack_blocked"] = bool(b.get("success_criterion_met"))
        entry["baseline_variants"] = _variant_flags(b)

    if s.get("skipped"):
        entry["secured"] = f"skipped ({s.get('reason', '')})"
    else:
        entry["secured_attack_blocked"] = bool(s.get("success_criterion_met"))
        entry["secured_variants"] = _variant_flags(s)
    return entry


def main():
    parser = argparse.ArgumentParser(description="evaluation metrics collector")
    parser.add_argument("--log", default="gateway_events.log")
    parser.add_argument("--baseline", default="evaluation/results/attack_results_baseline.json")
    parser.add_argument("--secured", default="evaluation/results/attack_results_secured.json")
    parser.add_argument("--overhead", default="evaluation/results/overhead.json")
    parser.add_argument("--normal", default="evaluation/results/normal_operation_secured.json")
    parser.add_argument("--output", default="evaluation/results/evaluation_summary.json")
    args = parser.parse_args()

    print("evaluation summary\n")
    log_counts = parse_event_log(args.log)
    baseline = load_json(args.baseline)
    secured = load_json(args.secured)
    overhead = load_json(args.overhead)
    normal = load_json(args.normal)

    attacks = {name: summarise_attack(name, baseline, secured) for name in ATTACKS}
    secured_blocked = sum(
        1 for a in attacks.values() if a.get("secured_attack_blocked")
    )
    secured_run = sum(
        1 for a in attacks.values() if "secured_attack_blocked" in a
    )

    summary = {
        "attacks": attacks,
        "secured_attacks_blocked": f"{secured_blocked}/{secured_run}",
        "gateway_log_summary": log_counts,
        "normal_operation": normal,
        "overhead": overhead,
    }

    for name, data in attacks.items():
        print(f"{name}  ({data['blocked_by']})")
        for k, v in data.items():
            if k == "blocked_by":
                continue
            print(f"  {k}: {v}")
        print("")

    print(f"secured attacks blocked: {secured_blocked}/{secured_run}")
    if normal:
        print(f"normal-operation false-positive rate: {normal.get('false_positive_rate')}")
    if overhead:
        print(f"gateway added overhead (mean): {overhead.get('gateway_added_overhead_mean_ms')} ms")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nsaved to {args.output}")


if __name__ == "__main__":
    main()
