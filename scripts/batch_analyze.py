"""Analyse every APK in a folder and store one JSON result per unique SHA-256.

Usage: python scripts/batch_analyze.py <apk_folder>
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from backend.engine import pipeline  # noqa: E402
from backend import store  # noqa: E402


def main(folder):
    files = sorted(f for f in os.listdir(folder) if f.lower().endswith(".apk"))
    for i, name in enumerate(files, 1):
        path = os.path.join(folder, name)
        sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if store.exists(sha):
            store.add_alias(sha, name)
            print(f"[{i}/{len(files)}] {name}: duplicate of {sha[:12]}", flush=True)
            continue
        try:
            result = pipeline.analyze(path)
        except Exception as e:
            print(f"[{i}/{len(files)}] {name}: FAILED {e}", flush=True)
            continue
        store.save(result)
        r = result["risk"]
        print(f"[{i}/{len(files)}] {name}: {result['static']['package']} -> {r['score']} {r['level']} "
              f"({result['duration_s']}s)", flush=True)


if __name__ == "__main__":
    main(sys.argv[1])
