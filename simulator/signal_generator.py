from __future__ import annotations
import numpy as np


class SignalGenerator:
    def __init__(self, num_channels=8, sampling_rate=250):
        self.num_channels = num_channels
        self.sampling_rate = sampling_rate
        self.t = 0.0
        self.dt = 1.0 / sampling_rate

        rng = np.random.default_rng(42)
        self.phase_offsets = rng.uniform(0, 2 * np.pi, size=(num_channels, 5))

        self.amplitudes = rng.uniform(
            low=[20, 10, 15, 5, 3],
            high=[40, 20, 30, 15, 7],
            size=(num_channels, 5),
        )

        self.frequencies = rng.uniform(
            low=[0.5, 4, 8, 13, 0],
            high=[4, 8, 13, 30, 0],
            size=(num_channels, 5),
        )

        self._noise_state = np.zeros(num_channels)

    def next_sample(self) -> list[float]:
        t = self.t
        values = []
        for ch in range(self.num_channels):
            sample = 0.0
            for band in range(4):
                amp = self.amplitudes[ch, band]
                freq = self.frequencies[ch, band]
                phase = self.phase_offsets[ch, band]
                sample += amp * np.sin(2 * np.pi * freq * t + phase)

            white = np.random.normal(0, 1)
            self._noise_state[ch] = 0.99 * self._noise_state[ch] + 0.01 * white
            sample += self.amplitudes[ch, 4] * self._noise_state[ch] * 50

            values.append(round(float(sample), 2))

        self.t += self.dt
        return values


class FileSignalGenerator:
    def __init__(self, path, num_channels=8, sampling_rate=250):
        self.num_channels = num_channels
        arr = self._load(path)
        if arr.ndim == 1:
            arr = arr.reshape(-1, 1)

        cols = arr.shape[1]
        if cols >= num_channels:
            arr = arr[:, :num_channels]
        else:
            reps = int(np.ceil(num_channels / cols))
            arr = np.tile(arr, (1, reps))[:, :num_channels]

        mean = arr.mean(axis=0)
        std = arr.std(axis=0)
        std[std == 0] = 1.0
        arr = (arr - mean) / std * 45.0
        arr = np.clip(arr, -90, 90)

        self.data = np.round(arr, 2)
        self.idx = 0

    def _load(self, path):
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()

        start = 0
        for i, ln in enumerate(lines):
            if ln.strip().lower().startswith("@data"):
                start = i + 1
                break

        rows = []
        for ln in lines[start:]:
            s = ln.strip()
            if not s or s.startswith("%") or s.startswith("@"):
                continue
            parts = s.split(",") if "," in s else s.split()
            vals = []
            for p in parts:
                try:
                    vals.append(float(p))
                except ValueError:
                    pass
            if vals:
                rows.append(vals)

        if not rows:
            raise ValueError(f"no numeric rows found in EEG file: {path}")
        width = min(len(r) for r in rows)
        return np.array([r[:width] for r in rows], dtype=float)

    def next_sample(self) -> list[float]:
        row = self.data[self.idx]
        self.idx = (self.idx + 1) % len(self.data)
        return [float(x) for x in row]
