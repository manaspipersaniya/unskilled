"""Permission knowledge base: classifies Android permissions and explains abuse potential."""

# name -> (level, weight, why it matters for forensic analysts)
PERMISSIONS = {
    # SMS / OTP theft
    "READ_SMS": ("dangerous", 8, "Can read all SMS including bank OTPs"),
    "RECEIVE_SMS": ("dangerous", 8, "Can intercept incoming SMS/OTP in real time"),
    "SEND_SMS": ("dangerous", 7, "Can send SMS (premium fraud, worm spreading, OTP forwarding)"),
    "RECEIVE_MMS": ("dangerous", 3, "Can intercept MMS"),
    "RECEIVE_WAP_PUSH": ("dangerous", 3, "Can intercept WAP push messages"),
    # Telephony
    "READ_CALL_LOG": ("dangerous", 5, "Can read call history"),
    "WRITE_CALL_LOG": ("dangerous", 4, "Can tamper with call history"),
    "CALL_PHONE": ("dangerous", 5, "Can place calls without user interaction (USSD / call forwarding abuse)"),
    "PROCESS_OUTGOING_CALLS": ("dangerous", 5, "Can redirect/monitor outgoing calls"),
    "ANSWER_PHONE_CALLS": ("dangerous", 4, "Can answer calls programmatically"),
    "READ_PHONE_STATE": ("dangerous", 3, "Reads IMEI/SIM/phone number (device fingerprinting)"),
    "READ_PHONE_NUMBERS": ("dangerous", 4, "Reads the victim's phone number"),
    # Personal data
    "READ_CONTACTS": ("dangerous", 6, "Can exfiltrate contact list (used to spread lure APK)"),
    "WRITE_CONTACTS": ("dangerous", 3, "Can modify contacts"),
    "GET_ACCOUNTS": ("dangerous", 3, "Enumerates accounts on device"),
    "READ_CALENDAR": ("dangerous", 2, "Reads calendar"),
    "ACCESS_FINE_LOCATION": ("dangerous", 4, "Precise GPS tracking"),
    "ACCESS_COARSE_LOCATION": ("dangerous", 2, "Approximate location"),
    "ACCESS_BACKGROUND_LOCATION": ("dangerous", 5, "Tracks location while app is closed"),
    "RECORD_AUDIO": ("dangerous", 6, "Microphone recording / call recording"),
    "CAMERA": ("dangerous", 5, "Covert photo/video capture"),
    "READ_EXTERNAL_STORAGE": ("dangerous", 3, "Reads user files/photos"),
    "WRITE_EXTERNAL_STORAGE": ("dangerous", 2, "Writes to shared storage"),
    "MANAGE_EXTERNAL_STORAGE": ("dangerous", 6, "Full access to all files"),
    "READ_MEDIA_IMAGES": ("dangerous", 3, "Reads photos"),
    "BODY_SENSORS": ("dangerous", 2, "Reads body sensors"),
    # Abuse-prone special permissions
    "SYSTEM_ALERT_WINDOW": ("suspicious", 7, "Draw over other apps: overlay/phishing screens over bank apps"),
    "BIND_ACCESSIBILITY_SERVICE": ("suspicious", 10, "Accessibility: keylogging, screen reading, auto-clicking, self-granting permissions"),
    "BIND_DEVICE_ADMIN": ("suspicious", 9, "Device admin: prevents uninstall, can lock/wipe device"),
    "BIND_NOTIFICATION_LISTENER_SERVICE": ("suspicious", 7, "Reads all notifications incl. OTPs and chats"),
    "REQUEST_INSTALL_PACKAGES": ("suspicious", 6, "Can install other APKs (dropper behaviour)"),
    "REQUEST_DELETE_PACKAGES": ("suspicious", 4, "Can uninstall apps (e.g. security apps)"),
    "QUERY_ALL_PACKAGES": ("suspicious", 3, "Enumerates installed apps (target banking apps)"),
    "PACKAGE_USAGE_STATS": ("suspicious", 4, "Knows which app is in foreground (overlay timing)"),
    "WRITE_SETTINGS": ("suspicious", 3, "Modifies system settings"),
    "WRITE_SECURE_SETTINGS": ("suspicious", 8, "Modifies secure settings (normally system only)"),
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("suspicious", 3, "Avoids being killed by the OS (persistence)"),
    "RECEIVE_BOOT_COMPLETED": ("suspicious", 3, "Auto-starts at boot (persistence)"),
    "FOREGROUND_SERVICE": ("normal", 1, "Long running foreground service"),
    "USE_FULL_SCREEN_INTENT": ("suspicious", 3, "Full-screen pop-ups over lock screen"),
    "DISABLE_KEYGUARD": ("suspicious", 4, "Can disable lock screen"),
    "WAKE_LOCK": ("normal", 1, "Keeps device awake"),
    "BIND_VPN_SERVICE": ("suspicious", 5, "Can route all device traffic through itself"),
    "READ_LOGS": ("suspicious", 5, "Reads system logs"),
    "INSTALL_PACKAGES": ("suspicious", 8, "Silent install (system-level)"),
    "CHANGE_WIFI_STATE": ("normal", 1, "Changes Wi-Fi state"),
    "INTERNET": ("normal", 1, "Network access"),
    "ACCESS_NETWORK_STATE": ("normal", 0, "Network state"),
    "ACCESS_WIFI_STATE": ("normal", 0, "Wi-Fi state"),
    "VIBRATE": ("normal", 0, "Vibration"),
    "POST_NOTIFICATIONS": ("normal", 0, "Shows notifications"),
}


def classify(permissions):
    """Return a list of {name, short, level, weight, reason} for each requested permission."""
    out = []
    for full in sorted(set(permissions)):
        short = full.split(".")[-1]
        level, weight, reason = PERMISSIONS.get(short, ("custom" if not full.startswith("android.") else "normal", 0, ""))
        out.append({"name": full, "short": short, "level": level, "weight": weight, "reason": reason})
    return out


def summary(classified):
    counts = {"dangerous": 0, "suspicious": 0, "normal": 0, "custom": 0}
    for p in classified:
        counts[p["level"]] = counts.get(p["level"], 0) + 1
    return counts
