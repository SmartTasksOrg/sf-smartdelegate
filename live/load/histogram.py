"""A small fixed-bucket latency histogram: exact count/min/max/sum and
percentiles to the bucket width. Buckets are 0.1 ms wide up to 2 s, then one
overflow bucket; the exact max is kept alongside, so a tail beyond 2 s is
never hidden. Histograms from different worker processes merge by adding."""
from __future__ import annotations

from array import array

WIDTH_MS = 0.1
N_BUCKETS = 20000           # 0.1 ms * 20000 = 2 s
INF = N_BUCKETS


class Hist:
    __slots__ = ("buckets", "count", "min", "max", "sum")

    def __init__(self):
        self.buckets = array("Q", [0]) * 0 or array("Q", bytes(8 * (N_BUCKETS + 1)))
        self.count = 0
        self.min = float("inf")
        self.max = 0.0
        self.sum = 0.0

    def add(self, ms: float) -> None:
        b = int(ms / WIDTH_MS)
        if b > INF:
            b = INF
        self.buckets[b] += 1
        self.count += 1
        self.sum += ms
        if ms < self.min:
            self.min = ms
        if ms > self.max:
            self.max = ms

    def merge(self, other: "Hist") -> None:
        for i in range(N_BUCKETS + 1):
            self.buckets[i] += other.buckets[i]
        self.count += other.count
        self.sum += other.sum
        self.min = min(self.min, other.min)
        self.max = max(self.max, other.max)

    def percentile(self, p: float) -> float:
        if self.count == 0:
            return 0.0
        target = p * self.count
        seen = 0
        for i in range(N_BUCKETS + 1):
            seen += self.buckets[i]
            if seen >= target:
                return self.max if i == INF else min((i + 1) * WIDTH_MS, self.max)
        return self.max

    def mean(self) -> float:
        return self.sum / self.count if self.count else 0.0

    def summary(self) -> dict:
        return {"count": self.count, "min_ms": round(self.min, 3) if self.count else 0.0, "mean_ms": round(self.mean(), 3),
                "p50_ms": round(self.percentile(0.50), 3), "p90_ms": round(self.percentile(0.90), 3),
                "p99_ms": round(self.percentile(0.99), 3), "p99_9_ms": round(self.percentile(0.999), 3),
                "max_ms": round(self.max, 3)}

    def to_tuple(self) -> tuple:
        # compact form for crossing a process boundary: only non-zero buckets
        nz = [(i, self.buckets[i]) for i in range(N_BUCKETS + 1) if self.buckets[i]]
        return (self.count, self.min, self.max, self.sum, nz)

    @classmethod
    def from_tuple(cls, t) -> "Hist":
        h = cls()
        h.count, h.min, h.max, h.sum, nz = t
        for i, c in nz:
            h.buckets[i] = c
        return h
