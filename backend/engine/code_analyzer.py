"""Static code analysis over DEX bytecode: suspicious APIs, evasion code, hard-coded strings."""
import re
import zipfile

from androguard.core.dex import DEX

# category -> list of (signature substring, description). Signatures match invoke operands
# such as "Landroid/telephony/SmsManager;->sendTextMessage(...)".
API_RULES = {
    "sms": [
        ("Landroid/telephony/SmsManager;->sendTextMessage", "Sends SMS"),
        ("Landroid/telephony/SmsManager;->sendMultipartTextMessage", "Sends multipart SMS"),
        ("Landroid/telephony/SmsMessage;->createFromPdu", "Parses incoming SMS PDUs (OTP interception)"),
        ("Landroid/provider/Telephony$Sms", "Accesses SMS content provider"),
        ("content://sms", "Queries SMS inbox"),
        ("Landroid/telephony/SmsMessage;->getMessageBody", "Reads SMS body"),
        ("Landroid/telephony/SmsMessage;->getOriginatingAddress", "Reads SMS sender"),
        ("android.provider.Telephony.SMS_RECEIVED", "Listens for incoming SMS"),
    ],
    "accessibility": [
        ("Landroid/accessibilityservice/AccessibilityService;->performGlobalAction", "Performs global actions (back/home) automatically"),
        ("Landroid/view/accessibility/AccessibilityNodeInfo;->performAction", "Clicks/types into other apps' UI"),
        ("Landroid/accessibilityservice/AccessibilityService;->dispatchGesture", "Injects touch gestures"),
        ("Landroid/view/accessibility/AccessibilityEvent;->getText", "Reads on-screen text (keylogging)"),
        ("Landroid/accessibilityservice/AccessibilityService;->getRootInActiveWindow", "Reads active window content"),
        ("Landroid/accessibilityservice/AccessibilityService;->takeScreenshot", "Takes screenshots via accessibility"),
        ("ACCESSIBILITY_SETTINGS", "Opens accessibility settings to lure user"),
    ],
    "overlay": [
        ("Landroid/view/WindowManager;->addView", "Adds windows (possible overlay)"),
        ("TYPE_APPLICATION_OVERLAY", "Uses overlay window type"),
        ("Landroid/provider/Settings;->canDrawOverlays", "Checks overlay permission"),
        ("ACTION_MANAGE_OVERLAY_PERMISSION", "Requests overlay permission"),
        ("Landroid/app/usage/UsageStatsManager;->queryUsageStats", "Detects foreground app (overlay trigger)"),
        ("Landroid/app/ActivityManager;->getRunningTasks", "Detects foreground app"),
    ],
    "device_admin": [
        ("Landroid/app/admin/DevicePolicyManager;->lockNow", "Locks the device"),
        ("Landroid/app/admin/DevicePolicyManager;->wipeData", "Wipes the device"),
        ("Landroid/app/admin/DevicePolicyManager;->resetPassword", "Changes lock-screen password"),
        ("android.app.action.ADD_DEVICE_ADMIN", "Requests device admin rights"),
        ("Landroid/app/admin/DevicePolicyManager;->isAdminActive", "Checks device admin status"),
    ],
    "contacts_calls": [
        ("ContactsContract", "Reads contacts"),
        ("content://call_log", "Reads call log"),
        ("Landroid/provider/CallLog", "Reads call log"),
        ("Landroid/telecom/TelecomManager;->endCall", "Ends calls"),
        ("Landroid/telephony/TelephonyManager;->getDeviceId", "Reads IMEI"),
        ("Landroid/telephony/TelephonyManager;->getLine1Number", "Reads phone number"),
        ("Landroid/telephony/TelephonyManager;->getSimSerialNumber", "Reads SIM serial"),
        ("Landroid/telephony/TelephonyManager;->getSubscriberId", "Reads IMSI"),
        ("tel:*21*", "USSD call forwarding code"),
    ],
    "surveillance": [
        ("Landroid/media/MediaRecorder;->setAudioSource", "Records audio"),
        ("Landroid/hardware/Camera;->open", "Opens camera"),
        ("Landroid/hardware/camera2/CameraManager;->openCamera", "Opens camera (camera2)"),
        ("Landroid/media/projection/MediaProjection", "Screen recording / streaming"),
        ("Landroid/location/LocationManager;->requestLocationUpdates", "Tracks location"),
        ("Landroid/location/LocationManager;->getLastKnownLocation", "Reads last location"),
        ("Landroid/content/ClipboardManager;->getPrimaryClip", "Reads clipboard (crypto wallet / password theft)"),
        ("Landroid/service/notification/NotificationListenerService", "Reads notifications"),
    ],
    "files": [
        ("Landroid/os/Environment;->getExternalStorageDirectory", "Accesses external storage"),
        ("MANAGE_ALL_FILES_ACCESS_PERMISSION", "Requests all-files access"),
        ("Landroid/content/pm/PackageManager;->getInstalledPackages", "Lists installed apps"),
        ("Landroid/content/pm/PackageManager;->getInstalledApplications", "Lists installed apps"),
    ],
    "install_dropper": [
        ("Landroid/content/pm/PackageInstaller;->createSession", "Installs APKs via session API (bypasses restricted settings)"),
        ("Landroid/content/pm/PackageInstaller$Session;->openWrite", "Streams an APK into installer session"),
        ("application/vnd.android.package-archive", "Launches APK install intent"),
        ("REQUEST_INSTALL_PACKAGES", "Requests unknown-source install permission"),
        ("Landroid/content/pm/PackageManager;->setComponentEnabledSetting", "Hides app icon / toggles components"),
    ],
    "dynamic_loading": [
        ("Ldalvik/system/DexClassLoader;-><init>", "Loads DEX from file at runtime"),
        ("Ldalvik/system/InMemoryDexClassLoader;-><init>", "Loads DEX from memory (fileless)"),
        ("Ldalvik/system/PathClassLoader;-><init>", "Creates class loader"),
        ("Ldalvik/system/DexFile;->loadDex", "Loads DEX file"),
        ("Ljava/lang/System;->loadLibrary", "Loads native library"),
        ("Ljava/lang/System;->load(", "Loads native library from path"),
        ("Ljava/lang/reflect/Method;->invoke", "Reflection (hides API calls)"),
        ("Ljava/lang/Class;->forName", "Reflection class lookup"),
    ],
    "shell_exec": [
        ("Ljava/lang/Runtime;->exec", "Executes shell commands"),
        ("Ljava/lang/ProcessBuilder;-><init>", "Spawns processes"),
        ("/system/bin/su", "Root (su) check / use"),
        ("/system/xbin/su", "Root (su) check / use"),
    ],
    "anti_debug": [
        ("Landroid/os/Debug;->isDebuggerConnected", "Detects debugger"),
        ("Landroid/os/Debug;->waitingForDebugger", "Detects debugger"),
        ("TracerPid", "Reads TracerPid (ptrace detection)"),
        ("frida", "Looks for Frida instrumentation"),
        ("xposed", "Looks for Xposed hooks"),
        ("27042", "Frida default port check"),
    ],
    "anti_emulator": [
        ("goldfish", "Emulator kernel check"),
        ("ranchu", "Emulator kernel check"),
        ("ro.kernel.qemu", "QEMU property check"),
        ("generic_x86", "Emulator build check"),
        ("Genymotion", "Genymotion check"),
        ("sdk_gphone", "Emulator product check"),
        ("Landroid/os/Build;->FINGERPRINT", "Reads build fingerprint (emulator detection)"),
        ("000000000000000", "Null IMEI emulator check"),
    ],
    "crypto_obfuscation": [
        ("Ljavax/crypto/Cipher;->getInstance", "Uses encryption (payload/strings/C2)"),
        ("Ljavax/crypto/spec/SecretKeySpec;-><init>", "Hard-coded symmetric key"),
        ("Landroid/util/Base64;->decode", "Base64 decoding"),
        ("Ljava/util/zip/GZIPInputStream", "Decompresses embedded data"),
    ],
    "network": [
        ("Ljava/net/Socket;-><init>", "Raw TCP socket (RAT C2 channel)"),
        ("Ljava/net/HttpURLConnection", "HTTP communication"),
        ("Lokhttp3/OkHttpClient", "OkHttp client"),
        ("Landroid/webkit/WebView;->loadUrl", "Loads web content (phishing pages)"),
        ("Landroid/webkit/WebView;->addJavascriptInterface", "Exposes Java to JavaScript"),
        ("api.telegram.org", "Telegram bot exfiltration"),
        ("firebaseio.com", "Firebase backend"),
        ("Lcom/google/firebase/messaging", "Firebase Cloud Messaging (C2 commands via push)"),
    ],
}

INVOKE_OPS = set(range(0x6E, 0x73)) | set(range(0x74, 0x79)) | {0xFA, 0xFB}
LIBRARY_PREFIXES = ("Landroidx/", "Landroid/support/", "Lkotlin/", "Lkotlinx/", "Lcom/google/android/material/",
                    "Lcom/google/gson/", "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lio/reactivex/", "Lcom/squareup/",
                    "Lorg/bouncycastle/", "L_COROUTINE/", "Lorg/intellij/", "Lorg/jetbrains/", "Lcom/bumptech/",
                    "Lj$/", "Ljava/", "Ljavax/")

SECRET_PATTERNS = {
    "telegram_bot_token": r"\b\d{8,11}:AA[A-Za-z0-9_-]{33}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "firebase_url": r"https?://[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)",
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(?:com|in|net|org|ru|io|xyz|me)\b",
    "upi_id": r"\b[a-zA-Z0-9.\-_]{3,}@(?:ybl|okaxis|oksbi|okhdfcbank|paytm|upi|ibl|axl)\b",
    "phone_in": r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)",
    "password_kv": r"(?i)\b(?:password|passwd|pwd|secret|token|api_?key)\s*[:=]\s*['\"]?[^\s'\"]{4,}",
}


def _load_dex(zf):
    out = []
    for n in zf.namelist():
        if re.fullmatch(r"classes\d*\.dex", n):
            try:
                out.append((n, zf.read(n)))
            except Exception:
                pass
    return out


def analyze(path, max_dex_bytes=40 * 1024 * 1024, deep=True):
    zf = zipfile.ZipFile(path)
    dex_files = _load_dex(zf)
    total = sum(len(b) for _, b in dex_files)

    strings = set()
    hits = {}  # (category, sig) -> {"desc", "locations": set()}
    app_classes = 0
    class_names = []

    def add_hit(cat, sig, desc, loc):
        h = hits.setdefault((cat, sig), {"category": cat, "api": sig, "description": desc, "locations": set()})
        if loc and len(h["locations"]) < 12:
            h["locations"].add(loc)

    parsed_ok = True
    for name, raw in dex_files:
        try:
            d = DEX(raw)
        except Exception:
            parsed_ok = False
            strings.update(s.decode("utf-8", "ignore") for s in re.findall(rb"[\x20-\x7e]{6,}", raw))
            continue
        for s in d.get_strings():
            if 4 <= len(s) <= 4096:
                strings.add(s)
        if not deep or total > max_dex_bytes:
            continue
        for cls in d.get_classes():
            cname = cls.get_name()
            if cname.startswith(LIBRARY_PREFIXES):
                continue
            app_classes += 1
            if len(class_names) < 4000:
                class_names.append(cname)
            for m in cls.get_methods():
                loc = f"{cname[1:-1].replace('/', '.')}.{m.get_name()}"
                try:
                    for ins in m.get_instructions():
                        op = ins.get_op_value()
                        if op in INVOKE_OPS or op in (0x1A, 0x1B):  # invoke-* and const-string
                            out = ins.get_output()
                            for cat, rules in API_RULES.items():
                                for sig, desc in rules:
                                    if sig in out:
                                        add_hit(cat, sig, desc, loc)
                except Exception:
                    continue

    # Fallback / complement: string-table presence (catches reflection-hidden APIs)
    blob = "\n".join(strings)
    for cat, rules in API_RULES.items():
        for sig, desc in rules:
            key = sig.split(";->")[-1].split("(")[0] if ";->" in sig else sig
            if (cat, sig) not in hits and len(key) > 4 and key in blob:
                h = hits.setdefault((cat, sig), {"category": cat, "api": sig, "description": desc, "locations": set()})
                h["locations"].add("[string table]")

    findings = []
    for h in hits.values():
        h["locations"] = sorted(h["locations"])
        findings.append(h)
    findings.sort(key=lambda h: (h["category"], h["api"]))

    by_cat = {}
    for f in findings:
        by_cat.setdefault(f["category"], []).append(f)

    secrets = []
    for kind, pat in SECRET_PATTERNS.items():
        found = set()
        for s in strings:
            for m in re.findall(pat, s):
                found.add(m if isinstance(m, str) else m[0])
        for v in sorted(found)[:30]:
            secrets.append({"type": kind, "value": v})

    # Obfuscation heuristics on class names
    short = [c for c in class_names if re.fullmatch(r"L(?:[a-zA-Z0-9]{1,2}/)*[a-zA-Z0-9]{1,2};", c)]
    nonascii = [c for c in class_names if any(ord(ch) > 127 for ch in c)]
    obf_ratio = round((len(short) + len(nonascii)) / max(1, len(class_names)), 2)

    return {
        "dex_count": len(dex_files),
        "dex_total_bytes": total,
        "dex_parsed": parsed_ok,
        "deep_scan": deep and total <= max_dex_bytes,
        "app_class_count": app_classes,
        "api_findings": findings,
        "api_by_category": {k: len(v) for k, v in by_cat.items()},
        "secrets": secrets,
        "obfuscation": {
            "short_name_classes": len(short),
            "non_ascii_classes": len(nonascii),
            "ratio": obf_ratio,
            "sample": (nonascii or short)[:10],
        },
        "_strings": strings,  # internal, consumed by network/evasion modules; stripped before storage
    }
