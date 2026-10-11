"""Time each distribution's detection one at a time, bucketed by where the license came from."""

import time
from importlib.metadata import distributions

from trustedlicenses.detection import canonical_name, inspect_distribution

buckets: dict[str, list[float]] = {"metadata": [], "license-files": [], "none": []}
slow = []
total0 = time.perf_counter()
for dist in distributions():
    name = canonical_name(dist.metadata["Name"] or "")
    t0 = time.perf_counter()
    result = inspect_distribution(dist, name=name)
    dt = time.perf_counter() - t0
    src = result.source
    kind = "license-files" if src.startswith("license files") else "metadata" if result.keys else "none"
    buckets[kind].append(dt)
    if kind == "license-files":
        slow.append((dt, name))
print("total serial:", round(time.perf_counter() - total0, 2))
for k, v in buckets.items():
    print(k, len(v), round(sum(v), 2))
print(sorted(slow, reverse=True)[:5])
