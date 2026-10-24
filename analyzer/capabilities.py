"""Behavioural capabilities inferred from the Android APIs referenced in the DEX code.

This is API-usage analysis: it shows which sensitive APIs the code refers to and whether the
app also holds the permission those APIs need. It is static, so it shows what the code CAN do,
not what it does at runtime. An API that is referenced without its permission is usually unused
library code, so it is reported with a lower status.
"""
from typing import Any

# needle kinds: "class" (type descriptor), "method" (method name), "string" (literal text)
# permission names are the short form (without "android.permission.")
CAPABILITIES: list[dict[str, Any]] = [
    {"id": "sms_send", "label": "Send SMS", "tier": "high", "permissions": ["SEND_SMS"],
     "needles": [(b"Landroid/telephony/SmsManager;", "class"), (b"sendTextMessage", "method"),
                 (b"sendMultipartTextMessage", "method"), (b"sendDataMessage", "method")],
     "require_method": True, "mitre": ["T1582"]},
    {"id": "sms_read", "label": "Read or intercept SMS", "tier": "high",
     "permissions": ["READ_SMS", "RECEIVE_SMS"],
     "needles": [(b"android.provider.Telephony.SMS_RECEIVED", "string"), (b"content://sms", "string"),
                 (b"Landroid/provider/Telephony$Sms;", "class")],
     "require_method": False, "mitre": ["T1636.004"]},
    {"id": "contacts_read", "label": "Read contacts", "tier": "medium", "permissions": ["READ_CONTACTS"],
     "needles": [(b"Landroid/provider/ContactsContract", "class")],
     "require_method": False, "mitre": ["T1636.003"]},
    {"id": "call_log_read", "label": "Read call log", "tier": "high", "permissions": ["READ_CALL_LOG"],
     "needles": [(b"Landroid/provider/CallLog", "class")],
     "require_method": False, "mitre": ["T1636.002"]},
    {"id": "location", "label": "Track location", "tier": "medium",
     "permissions": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"],
     "needles": [(b"Landroid/location/LocationManager;", "class"), (b"requestLocationUpdates", "method"),
                 (b"getLastKnownLocation", "method")],
     "require_method": True, "mitre": ["T1430"]},
    {"id": "audio_record", "label": "Record audio", "tier": "high", "permissions": ["RECORD_AUDIO"],
     "needles": [(b"Landroid/media/AudioRecord;", "class"), (b"Landroid/media/MediaRecorder;", "class")],
     "require_method": False, "mitre": ["T1429"]},
    {"id": "camera", "label": "Use the camera", "tier": "medium", "permissions": ["CAMERA"],
     "needles": [(b"Landroid/hardware/camera2/CameraManager;", "class"), (b"Landroid/hardware/Camera;", "class")],
     "require_method": False, "mitre": ["T1512"]},
    {"id": "accessibility", "label": "Accessibility service control", "tier": "high",
     "permissions": ["BIND_ACCESSIBILITY_SERVICE"],
     "needles": [(b"Landroid/accessibilityservice/AccessibilityService;", "class"),
                 (b"performGlobalAction", "method"), (b"dispatchGesture", "method")],
     "require_method": False, "mitre": ["T1453"]},
    {"id": "device_admin", "label": "Device administrator control", "tier": "high",
     "permissions": ["BIND_DEVICE_ADMIN"],
     "needles": [(b"Landroid/app/admin/DevicePolicyManager;", "class"), (b"lockNow", "method"),
                 (b"wipeData", "method")],
     "require_method": True, "mitre": ["T1626.001"]},
    {"id": "package_install", "label": "Install other apps", "tier": "high",
     "permissions": ["REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES"],
     "needles": [(b"Landroid/content/pm/PackageInstaller;", "class"),
                 (b"application/vnd.android.package-archive", "string")],
     "require_method": False, "mitre": ["T1544"]},
    {"id": "notification_listener", "label": "Read notifications", "tier": "high",
     "permissions": ["BIND_NOTIFICATION_LISTENER_SERVICE"],
     "needles": [(b"Landroid/service/notification/NotificationListenerService;", "class")],
     "require_method": False, "mitre": ["T1517"]},
    {"id": "screen_capture", "label": "Capture the screen", "tier": "high", "permissions": [],
     "needles": [(b"Landroid/media/projection/MediaProjection;", "class")],
     "require_method": False, "mitre": ["T1513"]},
    {"id": "device_identifiers", "label": "Read device identifiers", "tier": "medium",
     "permissions": ["READ_PHONE_STATE"],
     "needles": [(b"Landroid/telephony/TelephonyManager;", "class"), (b"getDeviceId", "method"),
                 (b"getImei", "method"), (b"getSubscriberId", "method"), (b"getLine1Number", "method")],
     "require_method": True, "mitre": ["T1426"]},
    {"id": "clipboard", "label": "Access the clipboard", "tier": "low", "permissions": [],
     "needles": [(b"Landroid/content/ClipboardManager;", "class"), (b"getPrimaryClip", "method"),
                 (b"addPrimaryClipChangedListener", "method")],
     "require_method": True, "mitre": ["T1414"]},
]

TIER_ORDER = {"high": 0, "medium": 1, "low": 2}


def declared_permissions(result: dict[str, Any]) -> set[str]:
    """Permissions in uses-permission plus permissions set on components (such as BIND_* services)."""
    declared = {p["name"].replace("android.permission.", "") for p in result.get("permissions", [])}
    for comp in result.get("components", []):
        if comp.get("permission"):
            declared.add(comp["permission"].replace("android.permission.", ""))
    return declared


def detect_capabilities(apk: Any, result: dict[str, Any]) -> list[dict[str, Any]]:
    blobs = list(apk.get_all_dex())
    declared = declared_permissions(result)
    found: list[dict[str, Any]] = []
    for cap in CAPABILITIES:
        hits = {kind: [n for n, k in cap["needles"] if k == kind and any(n in b for b in blobs)]
                for kind in ("class", "method", "string")}
        referenced = bool(hits["method"]) if cap["require_method"] else any(hits.values())
        if not referenced:
            continue
        needed = cap["permissions"]
        if not needed:
            status, backed = "no permission required", None
        elif declared & set(needed):
            status, backed = "declared and used", True
        else:
            status, backed = "referenced only", False
        apis = [n.decode("ascii", "ignore") for kind in ("method", "class", "string") for n in hits[kind]]
        found.append({"id": cap["id"], "label": cap["label"], "tier": cap["tier"], "apis": apis[:6],
                      "permissions": needed, "permission_declared": backed, "status": status,
                      "mitre": cap["mitre"]})
    return sorted(found, key=lambda c: (TIER_ORDER[c["tier"]], c["label"]))
