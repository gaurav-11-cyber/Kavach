"""Static manifest analysis: basic info, permissions, exported components."""
from androguard.core.apk import APK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Step 3: loader
def load_apk(path):
    return APK(path)


def get_basic_info(apk):
    return {
        "package": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version": apk.get_androidversion_name(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
    }


# Step 4: permissions
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.RECEIVE_BOOT_COMPLETED",
}


def get_permissions(apk):
    return [
        {"name": p, "dangerous": p in DANGEROUS_PERMISSIONS}
        for p in sorted(apk.get_permissions())
    ]


# Step 5: exported components
def _full_name(name, package):
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def get_components(apk):
    """Return activities, services, receivers, providers with exported status.

    A component is exported if exported="true", or if exported is not set
    and it has an intent-filter (old default behaviour).
    """
    package = apk.get_package()
    manifest = apk.get_android_manifest_xml()
    components = []
    for kind in ("activity", "service", "receiver", "provider"):
        for node in manifest.findall(".//" + kind):
            raw_name = node.get(ANDROID_NS + "name")
            if not raw_name:
                continue
            exported_attr = node.get(ANDROID_NS + "exported")
            has_filter = node.find("intent-filter") is not None
            exported = exported_attr == "true" or (
                exported_attr is None and has_filter
            )
            components.append({
                "type": kind,
                "name": _full_name(raw_name, package),
                "exported": exported,
                "has_intent_filter": has_filter,
                "permission": node.get(ANDROID_NS + "permission"),
            })
    return components
