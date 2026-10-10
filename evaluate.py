"""Compare scanner output with hand-written ground truth (precision / recall / scan time)."""
import json
import time
from pathlib import Path

from scanner.engine import scan_file

DIR = Path("sample_configs")
truth = json.loads((DIR / "ground_truth.json").read_text())

tp = fp = fn = 0
print(f"{'file':<24}{'TP':>4}{'FP':>4}{'FN':>4}{'scan ms':>10}")
times = []
for name, expected in truth.items():
    path = DIR / name
    t0 = time.perf_counter()
    for _ in range(50):
        found = scan_file(path)
    ms = (time.perf_counter() - t0) / 50 * 1000
    times.append(ms)
    got = {f"{f['rule_id']}:{f['resource']}" for f in found}
    exp = set(expected)
    a, b, c = len(got & exp), len(got - exp), len(exp - got)
    tp, fp, fn = tp + a, fp + b, fn + c
    print(f"{name:<24}{a:>4}{b:>4}{c:>4}{ms:>10.2f}")
    for x in sorted(got - exp):
        print("   false positive:", x)
    for x in sorted(exp - got):
        print("   missed:", x)

precision = tp / (tp + fp) if tp + fp else 1.0
recall = tp / (tp + fn) if tp + fn else 1.0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
print(f"\nTotals: TP={tp} FP={fp} FN={fn}")
print(f"Precision={precision:.2%}  Recall={recall:.2%}  F1={f1:.2%}")
print(f"Average scan time: {sum(times)/len(times):.2f} ms per config")
