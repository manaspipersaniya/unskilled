"""
Retroactively re-scores all cached JSON results using the updated _score() logic.
Run once after updating pipeline.py:
    python scripts/rescore.py
"""
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engine.pipeline import _score
from backend import store

updated = 0
for fn in os.listdir(store.RESULTS):
    if not fn.endswith(".json"):
        continue
    sha = fn[:-5]
    r = store.load(sha)
    old_score = r["risk"]["score"]
    old_level = r["risk"]["level"]
    # Re-run scoring on cached analysis data
    new_risk = _score(r["static"], r["code"], r["network"], r["evasion"])
    r["risk"] = new_risk
    store.save(r)
    new_score = new_risk["score"]
    new_level = new_risk["level"]
    if old_score != new_score or old_level != new_level:
        print(f"  {r['static']['file_name']:12s}  {old_score:3d} {old_level:8s} -> {new_score:3d} {new_level}")
        updated += 1

print(f"\nDone. Updated {updated} records out of {len(os.listdir(store.RESULTS))}.")
