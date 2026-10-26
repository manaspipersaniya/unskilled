"""Records a captioned, narrated walkthrough video of the dashboard.

Needs the API server running on :8000. Uses the system Microsoft Edge for recording
and edge-tts (Microsoft neural voices, online) for narration.
    python scripts/record_demo.py            -> demo/apk_forensics_demo.mp4
"""
import asyncio
import glob
import os
import shutil
import subprocess
import time

import edge_tts
from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "demo")
WORK = os.path.join(OUT, "_work")
URL = "http://localhost:8000"
W, H = 1280, 720
VOICE = os.environ.get("DEMO_VOICE", "en-US-AndrewNeural")
GAP = 0.7  # silence after each narration line, seconds

CAPTION_JS = """([title, text]) => {
  let c = document.getElementById('__cap');
  if (!c) {
    c = document.createElement('div'); c.id = '__cap';
    c.style.cssText = 'position:fixed;left:50%;bottom:28px;transform:translateX(-50%);z-index:9999;max-width:900px;' +
      'background:rgba(10,13,20,.94);border:1px solid #f59e0b;border-radius:10px;padding:12px 20px;' +
      'font:14px Inter,sans-serif;color:#e2e8f0;box-shadow:0 8px 30px rgba(0,0,0,.6);text-align:center;transition:opacity .3s';
    document.body.appendChild(c);
  }
  c.innerHTML = '<div style="font:700 11px JetBrains Mono,monospace;color:#f59e0b;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">'
    + title + '</div>' + text;
  c.style.opacity = text ? 1 : 0;
}"""

CARD_JS = """([big, small]) => {
  let c = document.getElementById('__card');
  if (!big) { if (c) c.remove(); return; }
  if (!c) { c = document.createElement('div'); c.id = '__card'; document.body.appendChild(c); }
  c.style.cssText = 'position:fixed;inset:0;z-index:10000;background:radial-gradient(circle at 50% 40%,#1a2235,#0a0d14 70%);' +
    'display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Inter,sans-serif;text-align:center';
  c.innerHTML = '<div style="font:600 13px JetBrains Mono,monospace;color:#f59e0b;letter-spacing:.2em">TEAM CH26-2834 · PS-02</div>'
    + '<div style="font-size:44px;font-weight:700;color:#e2e8f0;margin:14px 0">' + big + '</div>'
    + '<div style="font-size:17px;color:#94a3b8;max-width:820px;line-height:1.6">' + small + '</div>';
}"""

# (key, caption title, caption text, narration)
SCRIPT = [
    ("intro", "", "",
     "This is our AI-assisted Android application security and forensic analysis platform, built by team "
     "C H 26 28 34 for problem statement P S 02. It helps investigators triage suspicious Android apps quickly, "
     "backed by evidence they can explain and defend."),
    ("overview", "1 · Intelligence dashboard",
     "Every APK in the case batch-analysed: risk levels, packer detection, IoC totals and top package clusters",
     "The intelligence dashboard summarises the entire case. Every unique sample has been analysed in batch. "
     "We can see the risk distribution, how many samples are protected by packers, the hard-coded IP addresses "
     "and domains, and the package families that appear most often."),
    ("overview2", "1 · Intelligence dashboard", "Highest-risk samples are surfaced first, ready to open",
     "The highest-risk samples are listed first, so an investigator knows exactly where to start."),
    ("library", "2 · APK library",
     "Search, sort and filter every sample by risk level or packing status; export to CSV",
     "The APK library holds every sample. Investigators can filter by risk level or packing status, "
     "sort any column, and export the current view to CSV for the case file."),
    ("search", "2 · APK library", "Instant search across file name, package, app name and SHA-256",
     "Search works instantly across file names, package names, app names and SHA-256 hashes."),
    ("risk", "3 · Explainable risk score",
     "Every point is justified: verdict, per-module breakdown and the exact evidence behind the score",
     "Opening a sample shows its risk score, and the score is fully explainable. Every point is tied to a "
     "specific piece of evidence, and the breakdown bar shows how much came from permissions, code, evasion, "
     "manifest and network findings. The complete analysis can be exported as JSON, or as a printable report."),
    ("static", "4 · Static analysis",
     "Hashes, version, SDK levels, signing schemes, certificate anomalies and exported components",
     "Static analysis extracts file hashes, version and SDK levels, signing schemes and certificate details. "
     "Certificate anomalies, such as apps signed with publicly known test keys, are flagged automatically."),
    ("permissions", "5 · Permission analysis",
     "Permissions classified dangerous / suspicious / normal with the reason each one matters",
     "Every permission is classified as dangerous, suspicious or normal, with a plain-language reason explaining "
     "why it matters, for example reading SMS messages or drawing over other apps."),
    ("code", "6 · Code & API analysis",
     "DEX bytecode scanned for sensitive API use (SMS, accessibility, overlays...), secrets and obfuscation",
     "Code analysis scans the DEX bytecode for sensitive API calls. Categories such as accessibility abuse, "
     "which banking trojans use to read the screen and act on the victim's behalf, are highlighted. "
     "Hard-coded secrets and the level of obfuscation are measured as well."),
    ("evasion", "7 · Evasion & packer detection",
     "APKiD signatures, ZIP tampering, encrypted payloads and anti-analysis tricks",
     "Evasion analysis detects packers and anti-analysis tricks, using APKiD signatures, ZIP structure "
     "tampering, encrypted payloads and anti-emulator checks."),
    ("iocs", "8 · Indicators of compromise",
     "IPs, domains, URLs, hashes and cert fingerprints; click to copy, export as JSON",
     "All indicators of compromise, including IP addresses, domains, URLs, file hashes and certificate "
     "fingerprints, are collected in one place. Any indicator can be copied with a single click, or exported "
     "for sharing with other agencies."),
    ("manifest", "9 · Decoded manifest", "Full AndroidManifest.xml for manual review",
     "The decoded Android manifest is also available for manual verification."),
    ("ai", "10 · AI forensic assistant",
     "Claude writes the case summary and answers investigator questions "
     "(offline rule-based fallback shown here, no API key set)",
     "The AI assistant uses Claude to write a forensic summary and answer investigator questions, grounded in "
     "the extracted evidence. In this recording no API key is configured, so the built-in rule-based summary "
     "is shown instead."),
    ("campaigns", "11 · Campaign clustering", "Samples sharing a package are grouped; re-signed variants are flagged",
     "Campaign clustering groups samples that share a package name. The largest cluster here contains "
     "twenty-eight samples signed with twenty different certificates, a strong sign of one malware family "
     "being repeatedly re-signed to evade detection."),
    ("graph", "12 · Link graph",
     "APKs linked through shared packages, certificates, IPs and domains: shared infrastructure stands out",
     "The link graph connects samples through shared packages, certificates, IP addresses and domains, "
     "so common infrastructure across a campaign stands out visually."),
    ("compare", "13 · Sample comparison",
     "Side-by-side diff of permissions, APIs, evasion and IoCs with a similarity score",
     "Any two samples can be compared side by side. A high similarity score across permissions, APIs, "
     "evasion techniques and indicators suggests the samples belong to the same family."),
    ("upload", "14 · Upload new evidence", "Drop any APK: it is hashed, deduplicated and fully analysed server-side",
     "New evidence can be uploaded at any time. Each APK is hashed, de-duplicated, and run through the full "
     "analysis pipeline on the server."),
    ("outro", "", "",
     "Faster triage. Explainable evidence. AI-assisted reporting. Thank you."),
]


async def _tts_all():
    for key, _, _, text in SCRIPT:
        await edge_tts.Communicate(text, VOICE, rate="-4%").save(os.path.join(WORK, f"{key}.mp3"))


def _duration(path):
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
                         capture_output=True, text=True, check=True).stdout
    return float(out.strip())


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    print("Generating narration…")
    asyncio.run(_tts_all())
    durations = {k: _duration(os.path.join(WORK, f"{k}.mp3")) for k, *_ in SCRIPT}
    lines = {k: (t, c) for k, t, c, _ in SCRIPT}
    starts = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", args=["--disable-gpu"])
        ctx = browser.new_context(viewport={"width": W, "height": H},
                                  record_video_dir=os.path.join(WORK, "raw"), record_video_size={"width": W, "height": H})
        page = ctx.new_page()
        t0 = time.monotonic()
        wait = page.wait_for_timeout
        card = lambda big, small="": page.evaluate(CARD_JS, [big, small])

        def scene(key, action=None):
            """Shows the caption, starts narration, runs the action, then holds until narration ends."""
            starts[key] = time.monotonic() - t0
            title, text = lines[key]
            page.evaluate(CAPTION_JS, [title, text])
            if action:
                action()
            left = durations[key] + GAP - (time.monotonic() - t0 - starts[key])
            if left > 0:
                wait(int(left * 1000))

        def scroll(el, top):
            page.evaluate(f"document.getElementById('{el}').scrollTo({{top:{top},behavior:'smooth'}})")

        page.goto(URL)
        page.wait_for_selector("#stats-grid .stat-card")
        card("AI-Assisted Android APK<br>Forensic Analysis Platform",
             "Static, code, network and evasion analysis with explainable risk scoring, "
             "IoC extraction, campaign linking and AI-assisted reporting for investigators")
        wait(800)
        scene("intro")
        card("")

        scene("overview", lambda: (wait(2500), page.mouse.move(400, 330), wait(1200), page.mouse.move(700, 330)))
        scene("overview2", lambda: (scroll("main", 420), wait(2500)))
        scroll("main", 0)

        def library():
            page.click("#nav-apks"); wait(2500)
            page.click(".filter-btn[data-level='Critical']"); wait(2000)
            page.click(".filter-btn[data-level='packed']"); wait(2000)
            page.click(".filter-btn[data-level='all']"); wait(800)
            page.click("th[data-col='size']"); wait(1500)
            page.click("th[data-col='score']")
        scene("library", library)

        def search():
            page.click("#search-input")
            page.keyboard.type("cristal", delay=110); wait(2500)
            page.fill("#search-input", ""); page.dispatch_event("#search-input", "input")
        scene("search", search)

        def risk():
            # Open the Critical sample with the richest IoCs so every tab has something to show
            page.evaluate("""() => {
              const c = _apks.filter(a => a.level === 'Critical');
              const n = a => a.iocs.ips + a.iocs.domains + a.iocs.urls;
              openDetail(c.sort((a, b) => n(b) - n(a))[0].sha256);
            }""")
            page.wait_for_selector(".risk-header")
        scene("risk", risk)

        def tab(name, extra=None):
            def run():
                page.click(f".modal-tab[data-tab='{name}']"); wait(1800)
                if extra:
                    extra()
            return run

        def expand_api():
            if page.locator(".api-cat-header").count():
                page.click(".api-cat-header >> nth=0")
            wait(2500); scroll("modal-overlay", 300); wait(2500); scroll("modal-overlay", 0)

        def copy_ioc():
            if page.locator(".ioc-chip.copyable").count():
                page.click(".ioc-chip.copyable >> nth=0")

        scene("static", tab("static"))
        scene("permissions", tab("permissions", lambda: (wait(1500), scroll("modal-overlay", 300))))
        scroll("modal-overlay", 0)
        scene("code", tab("code", expand_api))
        scene("evasion", tab("evasion", lambda: (wait(1500), scroll("modal-overlay", 250))))
        scroll("modal-overlay", 0)
        scene("iocs", tab("iocs", lambda: (wait(2500), copy_ioc())))
        scene("manifest", tab("manifest"))

        def ai():
            page.click(".modal-tab[data-tab='ai']"); wait(1500)
            page.click("#gen-summary-btn")
            page.wait_for_function("!document.getElementById('gen-summary-btn').disabled", timeout=60000)
        scene("ai", ai)
        page.click("#modal-close"); wait(600)

        def campaigns():
            page.click("#nav-campaigns")
            page.wait_for_selector(".campaign-card"); wait(2500)
            page.click(".campaign-card >> nth=0")
        scene("campaigns", campaigns)

        def graph():
            page.click("#nav-graph")
            page.fill("#min-score-input", "85")
            page.click("#load-graph-btn")
        scene("graph", graph)

        def compare():
            page.click("#nav-compare"); wait(1500)
            page.click("#do-compare-btn")
            page.wait_for_selector(".similarity-pct"); wait(3000)
            scroll("main", 400)
        scene("compare", compare)

        def upload():
            page.click("#nav-upload"); wait(2000)
            apks = glob.glob(os.path.join(ROOT, "data", "uploads", "*.apk"))
            if apks:
                # Upload a copy: the server replaces uploads/<sha>.apk, which Windows refuses while the browser reads it
                sample = os.path.join(WORK, "evidence_sample.apk")
                shutil.copy(apks[0], sample)
                page.set_input_files("#file-input", sample)
                page.wait_for_function("/^[✓✗]/.test(document.querySelector('#upload-status .status')?.textContent||'')",
                                       timeout=120000)
        scene("upload", upload)

        page.evaluate(CAPTION_JS, ["", ""])
        card("Faster triage. Explainable evidence.",
             "Static · Code · Network · Evasion · IoCs · Campaigns · AI reporting<br><br>"
             "<span style='color:#f59e0b'>Team CH26-2834</span>")
        scene("outro")
        wait(1500)

        video = page.video.path()
        ctx.close()
        browser.close()

    print("Mixing narration…")
    keys = [k for k, *_ in SCRIPT]
    inputs = ["-i", video]
    for k in keys:
        inputs += ["-i", os.path.join(WORK, f"{k}.mp3")]
    delays = ";".join(f"[{i + 1}:a]adelay={int(starts[k] * 1000)}:all=1[a{i}]" for i, k in enumerate(keys))
    mix = "".join(f"[a{i}]" for i in range(len(keys))) + f"amix=inputs={len(keys)}:normalize=0[aout]"
    out = os.path.join(OUT, "apk_forensics_demo.mp4")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *inputs, "-filter_complex", f"{delays};{mix}",
                    "-map", "0:v", "-map", "[aout]", "-c:v", "libx264", "-preset", "medium", "-crf", "22",
                    "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart", out], check=True)
    shutil.rmtree(WORK, ignore_errors=True)
    print(out)


if __name__ == "__main__":
    main()
