"""Packer, obfuscation and anti-analysis detection (ZIP tampering, encrypted payloads, APKiD rules)."""
import math
import os
import re
import struct
from collections import Counter

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "apkid_compiled.yarc")
CUSTOM_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "custom.yara")

# Native libraries / asset markers left behind by commercial and underground packers.
PACKER_SIGNATURES = {
    "libnp_protect_res.so": "NP Manager (np protect) – encrypts resources/assets, control-flow obfuscation",
    "protected_by_np": "NP Manager protection marker",
    "DexCoder.so": "DexCoder packer – DEX encryption",
    "rizalprotect": "RizalProtect packer",
    "apk.crazy": "APK Crazy obfuscator",
    "apv-crazy": "APK Crazy obfuscator",
    "libjiagu": "Qihoo 360 Jiagu",
    "libsecexe.so": "Bangcle",
    "libDexHelper": "SecNeo / Bangcle DexHelper",
    "libshell": "Generic shell packer",
    "libprotectClass": "Protector class loader",
    "libtup.so": "Tencent Legu",
    "libexec.so": "Ijiami",
    "libapkprotect": "APKProtect",
    "libmobisec": "Alibaba mobisec",
    "libvirbox": "Virbox protector",
    "libnesec.so": "NetEase Yidun",
    "classes.dex.dat": "Encrypted DEX placeholder (packer stub)",
    "libjpush": None,  # common benign SDK – ignored
}
MAGIC = {
    b"PK\x03\x04": "zip/apk/jar", b"dex\n": "dex", b"\x7fELF": "elf", b"\x89PNG": "png", b"\xff\xd8\xff": "jpeg",
    b"GIF8": "gif", b"RIFF": "riff/webp", b"\x1f\x8b": "gzip", b"7z\xbc\xaf": "7z", b"<?xml": "xml",
    b"\x03\x00\x08\x00": "axml", b"\x02\x00\x0c\x00": "arsc", b"%PDF": "pdf", b"Rar!": "rar",
}
EXT_EXPECT = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "riff/webp", ".so": "elf",
              ".dex": "dex", ".apk": "zip/apk/jar", ".jar": "zip/apk/jar", ".zip": "zip/apk/jar"}

_rules = None


def _yara_rules():
    global _rules
    if _rules is None:
        try:
            import yara
            _rules = [yara.load(os.path.abspath(RULES_PATH))]
            if os.path.exists(CUSTOM_RULES_PATH):
                _rules.append(yara.compile(filepath=os.path.abspath(CUSTOM_RULES_PATH)))
        except Exception:
            _rules = []
    return _rules


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return round(-sum(v / n * math.log2(v / n) for v in c.values()), 3)


def _magic(data):
    for sig, kind in MAGIC.items():
        if data.startswith(sig):
            return kind
    return None


def _zip_structure(path):
    """Parse the central directory manually so tampered archives are still inspected."""
    entries, anomalies = [], []
    with open(path, "rb") as f:
        raw = f.read()
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0:
        return entries, ["No end-of-central-directory record"], raw
    cd_size, cd_off = struct.unpack("<II", raw[eocd + 12:eocd + 20])
    total = struct.unpack("<H", raw[eocd + 10:eocd + 12])[0]
    p = cd_off
    seen = Counter()
    while p < len(raw) - 46 and raw[p:p + 4] == b"PK\x01\x02":
        (flags, method, mtime, mdate, crc, csize, usize, nlen, xlen, clen) = struct.unpack(
            "<HHHHIIIHHH", raw[p + 8:p + 34])
        lho = struct.unpack("<I", raw[p + 42:p + 46])[0]
        name = raw[p + 46:p + 46 + nlen].decode("utf-8", "replace")
        year = ((mdate >> 9) & 0x7F) + 1980
        entries.append({"name": name, "method": method, "flags": flags, "csize": csize, "usize": usize,
                        "year": year, "offset": lho})
        seen[name] += 1
        p += 46 + nlen + xlen + clen
    if len(entries) != total:
        anomalies.append(f"Central directory count mismatch ({len(entries)} parsed vs {total} declared)")
    bad_methods = [e for e in entries if e["method"] not in (0, 8)]
    if bad_methods:
        anomalies.append(f"{len(bad_methods)} entries use invalid compression methods "
                         f"(e.g. {bad_methods[0]['name'][:40]} → method {bad_methods[0]['method']}); "
                         "Android ignores this but analysis tools crash")
    enc = [e for e in entries if e["flags"] & 1]
    if enc:
        anomalies.append(f"{len(enc)} entries flagged as encrypted (fake-encryption ZIP trick)")
    dups = [n for n, c in seen.items() if c > 1]
    if dups:
        anomalies.append(f"Duplicate ZIP entries ({len(dups)}), e.g. {dups[0][:60]}")
    return entries, anomalies, raw


def _read_entry(raw, e):
    """Read an entry's bytes directly using its local header; treats unknown methods as deflate/stored."""
    import zlib
    off = e["offset"]
    if raw[off:off + 4] != b"PK\x03\x04":
        return None
    nlen, xlen = struct.unpack("<HH", raw[off + 26:off + 30])
    start = off + 30 + nlen + xlen
    size = e["csize"] or e["usize"]
    data = raw[start:start + size]
    if e["method"] == 0 or e["csize"] == e["usize"]:
        return data
    try:
        return zlib.decompressobj(-15).decompress(data, 64 * 1024 * 1024)
    except Exception:
        return data


def decode_np_strings(java_sources):
    """Decode NP-Manager style `short[] ^ key` string obfuscation found in decompiled Java."""
    arrays = {}
    for src in java_sources:
        for name, body in re.findall(r"short\[\] (\w+) = \{([^}]*)\}", src):
            arrays[name] = [int(x) for x in body.split(",") if x.strip().lstrip("-").isdigit()]
    out = set()
    for src in java_sources:
        for a, b, k in re.findall(r"\((\d+), (\d+), (\d+)\)", src):
            a, b, k = int(a), int(b), int(k)
            for arr in arrays.values():
                for ln in (b - a, b):
                    if 0 < ln < 300 and a + ln <= len(arr):
                        t = "".join(chr((arr[a + i] ^ k) & 0xFFFF) for i in range(ln))
                        if t.isprintable() and t.isascii() and sum(c.isalnum() for c in t) > len(t) * 0.6:
                            out.add(t)
    return sorted(out)


def analyze(path, apk=None, dex_strings=()):
    entries, zip_anomalies, raw = _zip_structure(path)
    findings = []

    def add(kind, severity, title, evidence):
        findings.append({"type": kind, "severity": severity, "title": title, "evidence": evidence})

    for a in zip_anomalies:
        add("zip_tampering", "high", "ZIP structure tampering", a)

    # Path-length / depth tricks used to hide payloads from extraction tools
    deep = [e for e in entries if e["name"].count("/") > 20 or len(e["name"]) > 255]
    if deep:
        e = max(deep, key=lambda x: x["usize"])
        add("path_obfuscation", "high", "Payload hidden behind extremely deep/long path",
            f"{len(deep)} entries; largest {e['usize']:,} bytes at depth {e['name'].count('/')} "
            f"(path length {len(e['name'])})")
    nonprint = [e for e in entries if re.search(r"[^\x20-\x7e]", e["name"]) and not e["name"].startswith("res/")]
    if len(nonprint) > 3:
        add("name_obfuscation", "medium", "Non-ASCII / unreadable entry names", f"{len(nonprint)} entries")
    # 1980/1981 are the fixed dates used by reproducible builds (F-Droid, Bazel) and are not suspicious
    old = [e for e in entries if 1981 < e["year"] < 2009]
    if len(old) > len(entries) * 0.5 and entries:
        add("timestomp", "low", "Timestamps forged (pre-2009)", f"{len(old)} of {len(entries)} entries dated {old[0]['year']}")

    # Per-entry content inspection
    embedded, high_entropy, mismatches, packers = [], [], [], set()
    for e in entries:
        name = e["name"]
        lname = name.lower()
        for sig, desc in PACKER_SIGNATURES.items():
            if desc and sig.lower() in lname:
                packers.add(desc)
        if e["usize"] < 512 or name.startswith("META-INF/") or name in ("resources.arsc",):
            continue
        interesting = (name.startswith("assets/") or "/" not in name or name.startswith("res/raw")
                       or name.endswith((".png", ".jpg", ".bin", ".dat", ".apk", ".jar", ".dex", ".so"))
                       or e["usize"] > 200_000)
        if not interesting or (name.startswith("res/") and name.endswith(".xml")):
            continue
        data = _read_entry(raw, e)
        if not data:
            continue
        kind = _magic(data[:8])
        ext = os.path.splitext(lname)[1]
        if kind in ("zip/apk/jar", "dex") and not re.fullmatch(r"classes\d*\.dex", name):
            embedded.append({"name": name[-120:], "type": kind, "size": e["usize"]})
        elif ext in EXT_EXPECT and kind and kind != EXT_EXPECT[ext] and not (ext == ".png" and kind == "jpeg"):
            mismatches.append({"name": name[-120:], "claimed": ext, "actual": kind})
        elif ext in EXT_EXPECT and kind is None and ext != ".so" and e["usize"] > 4096:
            ent = entropy(data[:262144])
            mismatches.append({"name": name[-120:], "claimed": ext, "actual": f"unknown (entropy {ent})"})
        if kind not in ("png", "jpeg", "gif", "riff/webp", "elf", "dex", "gzip", "zip/apk/jar", "7z", "rar") \
                and e["usize"] > 16384:
            ent = entropy(data[:262144])
            if ent > 7.5:
                high_entropy.append({"name": name[-120:], "size": e["usize"], "entropy": ent})

    if embedded:
        add("embedded_payload", "high", "Embedded APK/DEX/JAR inside package",
            "; ".join(f"{x['name']} ({x['type']}, {x['size']:,} B)" for x in embedded[:5]))
    if high_entropy:
        big = max(high_entropy, key=lambda x: x["size"])
        add("encrypted_payload", "high" if big["size"] > 200_000 else "medium",
            "Encrypted / packed blob (high entropy)",
            f"{len(high_entropy)} blobs; largest {big['size']:,} B entropy {big['entropy']} ({big['name'][-60:]})")
    if mismatches:
        add("disguised_file", "medium", "File extension does not match content",
            "; ".join(f"{m['name'][-50:]} claims {m['claimed']} but is {m['actual']}" for m in mismatches[:5]))
    for p in sorted(packers):
        add("packer", "high", "Packer / protector detected", p)

    # APKiD + custom YARA rules over DEX, native libs and manifest
    apkid = set()
    rules = _yara_rules()
    if rules:
        for e in entries:
            n = e["name"]
            if (re.fullmatch(r"classes\d*\.dex", n) or n.endswith(".so") or n == "AndroidManifest.xml") and e["usize"] < 60_000_000:
                data = _read_entry(raw, e)
                if not data:
                    continue
                for r in rules:
                    try:
                        for m in r.match(data=data, timeout=60):
                            tag = m.tags[0] if m.tags else "custom"
                            if tag in ("file_type", "compiler") and "dexlib" not in str(m.meta.get("description", "")):
                                continue
                            apkid.add((tag, m.meta.get("description", m.rule)))
                    except Exception:
                        continue
    for tag, desc in sorted(apkid):
        if tag in ("packer", "protector"):
            add("packer", "high", f"APKiD {tag}", desc)
        elif tag == "compiler" and "dexlib" in desc:
            add("repackaged", "medium", "DEX rebuilt with smali/dexlib (repackaged APK)", desc)
        elif tag in ("anti_vm", "anti_debug", "anti_disassembly"):
            pass  # summarised below
        elif tag == "obfuscator":
            add("obfuscation", "medium", "Obfuscator detected", desc)
        elif tag == "custom":
            add("yara", "high", "Custom YARA rule matched", desc)
    anti_vm = sorted(d for t, d in apkid if t == "anti_vm")
    anti_dbg = sorted(d for t, d in apkid if t in ("anti_debug", "anti_disassembly"))
    if anti_vm:
        add("anti_emulation", "medium" if len(anti_vm) >= 4 else "low", "Anti-emulator checks", ", ".join(anti_vm))
    if anti_dbg:
        add("anti_debug", "medium", "Anti-debugging checks", ", ".join(anti_dbg))

    sev_rank = {"high": 3, "medium": 2, "low": 1}
    findings.sort(key=lambda f: -sev_rank[f["severity"]])
    return {
        "findings": findings,
        "zip_entries": len(entries),
        "apkid": [{"tag": t, "description": d} for t, d in sorted(apkid)],
        "embedded_payloads": embedded,
        "high_entropy_blobs": high_entropy[:20],
        "is_packed": any(f["type"] in ("packer", "encrypted_payload", "embedded_payload") for f in findings),
    }
