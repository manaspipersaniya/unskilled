"""URL / domain / IP / cloud-backend extraction from DEX strings, assets and native libraries."""
import ipaddress
import re
import zipfile

URL_RE = re.compile(r"(?:https?|wss?|ftp|tcp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{3,200}")
IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{2,5}))?(?![\d.])")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|in|info|biz|site|online|club|app|dev|me|cc|tk|ml|ga|cf|gq|pw|live|shop|store|link|click|vip|icu|buzz|cyou|sbs|work|fun|space|host|website|tech|pro|co|us|uk|de|id|br|ir|su|ws|to|ly))\b", re.I)

BENIGN_DOMAINS = (
    "schemas.android.com", "android.com", "w3.org", "apache.org", "google.com", "googleapis.com", "gstatic.com",
    "googlesource.com", "github.com", "githubusercontent.com", "github.io", "xmlpull.org", "json.org", "xml.org",
    "xmlsoap.org", "ns.adobe.com", "purl.org", "mozilla.org", "jetbrains.com", "kotlinlang.org", "jsoup.org",
    "openssl.org", "bouncycastle.org", "example.com", "example.org", "localhost", "aomedia.org", "apple.com",
    "squareup.com", "junit.org", "sourceforge.net", "googlecode.com", "g.co", "goo.gle", "firebase.google.com",
    "crashlytics.com", "app-measurement.com", "youtube.com", "gradle.org", "oracle.com", "sun.com", "ietf.org",
    "unicode.org", "iana.org", "dagger.dev", "bumptech.github.io", "fdroid.org", "f-droid.org", "codeberg.org",
    "creativecommons.org", "opensource.org", "gnu.org", "microsoft.com", "facebook.com", "fb.com", "twitter.com",
    "exoplayer.dev", "material.io", "chromium.org", "webkit.org", "w3c.org", "ecma-international.org", "yandex.ru",
)
SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".icu", ".buzz", ".cyou", ".sbs",
                   ".click", ".vip", ".live", ".shop", ".online", ".site", ".fun", ".su", ".ru", ".cn")
CLOUD_PATTERNS = {
    "firebase_realtime_db": r"[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)",
    "firebase_storage": r"[a-z0-9-]+\.appspot\.com",
    "firebase_project": r"\"project_id\"\s*:\s*\"[a-z0-9-]+\"",
    "telegram_bot_api": r"api\.telegram\.org/bot[^\s\"']*",
    "telegram_link": r"t\.me/[A-Za-z0-9_+]{3,}",
    "discord_webhook": r"discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "aws_s3": r"[a-z0-9.-]+\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com",
    "ngrok": r"[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)",
    "pastebin": r"pastebin\.com/(?:raw/)?[A-Za-z0-9]+",
    "000webhost": r"[a-z0-9-]+\.000webhostapp\.com",
    "dynamic_dns": r"[a-z0-9-]+\.(?:duckdns\.org|no-ip\.(?:org|biz)|ddns\.net|hopto\.org)",
    "supabase": r"[a-z0-9]+\.supabase\.co",
}


def _is_benign(host):
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in BENIGN_DOMAINS)


def _valid_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if any(len(p) > 1 and p.startswith("0") for p in ip.split(".")):
        return None  # version strings like 002.001.003.002
    return {"public": addr.is_global, "private": addr.is_private, "loopback": addr.is_loopback}


def _collect_text(path, dex_strings):
    """Strings from DEX plus readable text from assets, resources and native libraries."""
    texts = list(dex_strings)
    zf = zipfile.ZipFile(path)
    for info in zf.infolist():
        n = info.filename
        if info.file_size > 8 * 1024 * 1024:
            continue
        if n.startswith("assets/") or n.endswith((".so", ".json", ".html", ".js", ".txt", ".properties", ".xml")) \
                and not n.startswith("res/"):
            try:
                data = zf.read(info)
            except Exception:
                continue
            texts.extend(s.decode("utf-8", "ignore") for s in re.findall(rb"[\x20-\x7e]{6,}", data))
    return texts


def analyze(path, dex_strings, extra_texts=()):
    texts = _collect_text(path, dex_strings) + list(extra_texts)
    urls, ips, domains, cloud = {}, {}, {}, {}
    for t in texts:
        for u in URL_RE.findall(t):
            u = u.rstrip(".,;)'\"")
            host = re.sub(r"^[a-z]+://", "", u).split("/")[0].split(":")[0].split("@")[-1].lower()
            if not host or _is_benign(host) or "%" in host:
                continue
            urls[u] = host
        for ip, port in IP_RE.findall(t):
            meta = _valid_public_ip(ip)
            if meta and not meta["loopback"] and ip not in ("0.0.0.0", "255.255.255.255"):
                key = f"{ip}:{port}" if port else ip
                ips[key] = meta
        for d in DOMAIN_RE.findall(t):
            if t.strip().lower() != d.lower():
                continue  # only standalone domain strings; embedded matches are mostly Java package names
            d = d.lower()
            if not _is_benign(d) and not re.search(r"\.(?:java|kt|class|xml|png|jpg|so|dex|json|html|js|txt)$", d) \
                    and not re.match(r"^(?:com|org|net|android|androidx|io|kotlin|java)\.[a-z0-9_]+\.", d):
                domains[d] = domains.get(d, 0) + 1
        for kind, pat in CLOUD_PATTERNS.items():
            for m in re.findall(pat, t, re.I):
                cloud.setdefault(kind, set()).add(m)

    for u, host in urls.items():
        domains[host] = domains.get(host, 0) + 1

    url_list = []
    for u, host in sorted(urls.items()):
        flags = []
        if u.startswith("http://"):
            flags.append("cleartext")
        if IP_RE.fullmatch(host):
            flags.append("raw-ip")
        if host.endswith(SUSPICIOUS_TLDS):
            flags.append("suspicious-tld")
        if re.search(r"\.(?:apk|dex|jar|zip|bin)(?:\?|$)", u):
            flags.append("payload-download")
        if "api.telegram.org" in u:
            flags.append("telegram-exfil")
        url_list.append({"url": u, "host": host, "flags": flags})

    domain_list = [{"domain": d, "count": c, "suspicious_tld": d.endswith(SUSPICIOUS_TLDS)}
                   for d, c in sorted(domains.items(), key=lambda x: -x[1])]
    ip_list = [{"ip": k, **v} for k, v in sorted(ips.items())]
    return {
        "urls": url_list[:300],
        "domains": domain_list[:300],
        "ips": ip_list[:200],
        "cloud": {k: sorted(v)[:20] for k, v in cloud.items()},
        "counts": {"urls": len(url_list), "domains": len(domain_list), "ips": len(ip_list),
                   "public_ips": sum(1 for i in ip_list if i["public"])},
    }
