from __future__ import annotations

import math


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 0.0)
    phat = successes / n
    denom = 1.0 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    margin = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def rate_with_ci(successes: int, n: int) -> dict:
    lo, hi = wilson_interval(successes, n)
    return {
        "successes": successes,
        "attempts": n,
        "rate": round(successes / n, 4) if n else 0.0,
        "ci95_lower": round(lo, 4),
        "ci95_upper": round(hi, 4),
    }
