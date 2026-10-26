"""Tiny JSON-file store: one document per APK, keyed by SHA-256."""
import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
RESULTS = os.path.join(DATA_DIR, "results")
UPLOADS = os.path.join(DATA_DIR, "uploads")
os.makedirs(RESULTS, exist_ok=True)
os.makedirs(UPLOADS, exist_ok=True)


def _path(sha):
    return os.path.join(RESULTS, f"{sha}.json")


def exists(sha):
    return os.path.exists(_path(sha))


def save(result):
    sha = result["static"]["hashes"]["sha256"]
    result.setdefault("aliases", [result["static"]["file_name"]])
    with open(_path(sha), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, default=list)
    return sha


def load(sha):
    with open(_path(sha), encoding="utf-8") as f:
        return json.load(f)


def add_alias(sha, name):
    r = load(sha)
    if name not in r.setdefault("aliases", []):
        r["aliases"].append(name)
        save(r)


def summaries():
    out = []
    for fn in os.listdir(RESULTS):
        if not fn.endswith(".json"):
            continue
        r = load(fn[:-5])
        s = r["static"]
        out.append({
            "sha256": s["hashes"]["sha256"], "file_name": s["file_name"], "aliases": r.get("aliases", []),
            "package": s["package"], "app_name": s["app_name"], "size": s["size"],
            "score": r["risk"]["score"], "level": r["risk"]["level"],
            "packed": r["evasion"]["is_packed"],
            "cert": (s["certificate"]["certificates"][0]["sha256"] if s["certificate"]["certificates"] else ""),
            "iocs": {"ips": len(r["iocs"]["ips"]), "domains": len(r["iocs"]["domains"]), "urls": len(r["iocs"]["urls"])},
        })
    return sorted(out, key=lambda x: -x["score"])
