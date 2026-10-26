"""FastAPI server: REST API + static dashboard.

Run: uvicorn backend.app:app --port 8000
"""
import hashlib
import os
import shutil
from collections import defaultdict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import ai, store
from .engine import pipeline

FRONTEND = os.path.join(os.path.dirname(__file__), "..", "frontend")
app = FastAPI(title="APK Forensics Platform")


def _get(sha):
    if not store.exists(sha):
        raise HTTPException(404, "Unknown APK")
    return store.load(sha)


@app.get("/api/apks")
def list_apks():
    return store.summaries()


@app.get("/api/apks/{sha}")
def get_apk(sha: str):
    r = _get(sha)
    r["static"].pop("manifest_xml", None)
    return r


@app.get("/api/apks/{sha}/manifest", response_class=HTMLResponse)
def manifest(sha: str):
    from html import escape
    return f"<pre>{escape(_get(sha)['static']['manifest_xml'])}</pre>"


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "Only .apk files are accepted")
    tmp = os.path.join(store.UPLOADS, "incoming.apk")
    with open(tmp, "wb") as f:
        shutil.copyfileobj(file.file, f)
    sha = hashlib.sha256(open(tmp, "rb").read()).hexdigest()
    dest = os.path.join(store.UPLOADS, f"{sha}.apk")
    os.replace(tmp, dest)
    if store.exists(sha):
        store.add_alias(sha, file.filename)
        return {"sha256": sha, "cached": True}
    result = pipeline.analyze(dest)
    result["static"]["file_name"] = file.filename
    result["aliases"] = [file.filename]
    store.save(result)
    return {"sha256": sha, "cached": False}


@app.get("/api/compare")
def compare(a: str, b: str):
    ra, rb = _get(a), _get(b)

    def sets(r):
        return {
            "permissions": {p["short"] for p in r["static"]["permissions"]},
            "api": {f["api"] for f in r["code"]["api_findings"]},
            "evasion": {f["title"] for f in r["evasion"]["findings"]},
            "ips": set(r["iocs"]["ips"]),
            "domains": set(r["iocs"]["domains"]),
        }
    sa, sb = sets(ra), sets(rb)
    out = {}
    for k in sa:
        out[k] = {"common": sorted(sa[k] & sb[k]), "only_a": sorted(sa[k] - sb[k]), "only_b": sorted(sb[k] - sa[k])}
    union = sum(len(sa[k] | sb[k]) for k in sa) or 1
    out["similarity"] = round(sum(len(sa[k] & sb[k]) for k in sa) / union, 2)
    out["a"] = {"package": ra["static"]["package"], "score": ra["risk"]["score"], "file": ra["static"]["file_name"]}
    out["b"] = {"package": rb["static"]["package"], "score": rb["risk"]["score"], "file": rb["static"]["file_name"]}
    return out


@app.get("/api/campaigns")
def campaigns():
    """Groups samples sharing a package name or signing certificate."""
    groups = defaultdict(list)
    for s in store.summaries():
        groups[s["package"]].append(s)
    return sorted(
        [{"package": k, "count": len(v), "max_score": max(x["score"] for x in v),
          "certificates": len({x["cert"] for x in v}), "samples": [x["sha256"] for x in v]}
         for k, v in groups.items()],
        key=lambda g: (-g["count"], -g["max_score"]))


@app.get("/api/graph")
def graph(min_score: int = 0):
    nodes, edges, seen = [], [], set()

    def node(nid, label, kind, **extra):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "label": label, "kind": kind, **extra})

    for s in store.summaries():
        if s["score"] < min_score:
            continue
        r = store.load(s["sha256"])
        aid = "apk:" + s["sha256"]
        node(aid, s["file_name"][:28], "apk", score=s["score"], level=s["level"])
        node("pkg:" + s["package"], s["package"], "package")
        edges.append({"from": aid, "to": "pkg:" + s["package"]})
        if s["cert"]:
            node("cert:" + s["cert"], "cert " + s["cert"][:10], "cert")
            edges.append({"from": aid, "to": "cert:" + s["cert"]})
        for ip in r["iocs"]["ips"][:15]:
            node("ip:" + ip, ip, "ip")
            edges.append({"from": aid, "to": "ip:" + ip})
        for d in r["iocs"]["domains"][:15]:
            node("dom:" + d, d, "domain")
            edges.append({"from": aid, "to": "dom:" + d})
    return {"nodes": nodes, "edges": edges}


class Question(BaseModel):
    question: str


@app.post("/api/ask/{sha}")
def ask(sha: str, q: Question):
    return ai.ask(_get(sha), q.question)


@app.post("/api/summary/{sha}")
def summary(sha: str):
    r = _get(sha)
    r["ai_summary"] = ai.summarize(r)
    store.save(r)
    return {"summary": r["ai_summary"]}


@app.get("/")
def index():
    return FileResponse(os.path.join(FRONTEND, "index.html"))


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
