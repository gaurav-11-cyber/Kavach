from analyzer.capabilities import CAPABILITIES, declared_permissions, detect_capabilities
from analyzer.mitre import TECHNIQUES, map_to_mitre
from tests.helpers import FakeApk, clean_result, finish, perm


def detect(dex: bytes, permissions=(), components=()):
    result = clean_result()
    result["permissions"] = [perm(p) for p in permissions]
    result["components"] = list(components)
    return {c["id"]: c for c in detect_capabilities(FakeApk(dex=dex), result)}


SMS_DEX = b"Landroid/telephony/SmsManager; sendTextMessage"


def test_clean_code_has_no_capabilities():
    assert detect(b"Lcom/example/Foo; Lcom/example/Bar;") == {}


def test_sms_api_with_permission_is_declared_and_used():
    caps = detect(SMS_DEX, ["SEND_SMS"])
    assert caps["sms_send"]["status"] == "declared and used"
    assert caps["sms_send"]["permission_declared"] is True
    assert "sendTextMessage" in caps["sms_send"]["apis"]


def test_sms_api_without_permission_is_referenced_only():
    """Library code often mentions APIs the app can never use without the permission."""
    caps = detect(SMS_DEX, ["INTERNET"])
    assert caps["sms_send"]["status"] == "referenced only"
    assert caps["sms_send"]["permission_declared"] is False


def test_class_alone_is_not_enough_when_a_method_is_required():
    assert "sms_send" not in detect(b"Landroid/telephony/SmsManager;", ["SEND_SMS"])
    assert "location" not in detect(b"Landroid/location/LocationManager;", ["ACCESS_FINE_LOCATION"])


def test_accessibility_permission_declared_on_a_service_counts():
    service = {"type": "service", "name": "x.S", "exported": True, "permission":
               "android.permission.BIND_ACCESSIBILITY_SERVICE"}
    dex = b"Landroid/accessibilityservice/AccessibilityService; performGlobalAction"
    assert detect(dex, [], [service])["accessibility"]["status"] == "declared and used"
    assert detect(dex)["accessibility"]["status"] == "referenced only"


def test_capability_without_a_required_permission():
    caps = detect(b"Landroid/media/projection/MediaProjection;")
    assert caps["screen_capture"]["status"] == "no permission required"
    assert caps["screen_capture"]["permission_declared"] is None


def test_results_are_sorted_high_tier_first():
    dex = SMS_DEX + b" getPrimaryClip Landroid/content/ClipboardManager; Landroid/provider/ContactsContract"
    tiers = [c["tier"] for c in detect_capabilities(
        FakeApk(dex=dex), {**clean_result(), "permissions": [perm("SEND_SMS"), perm("READ_CONTACTS")]})]
    assert tiers == sorted(tiers, key=["high", "medium", "low"].index)


def test_declared_permissions_merges_manifest_and_components():
    result = {"permissions": [perm("SEND_SMS")],
              "components": [{"permission": "android.permission.BIND_DEVICE_ADMIN"}, {"permission": None}]}
    assert declared_permissions(result) == {"SEND_SMS", "BIND_DEVICE_ADMIN"}


def test_every_capability_maps_to_a_known_mitre_technique():
    for cap in CAPABILITIES:
        assert cap["mitre"] and all(t in TECHNIQUES for t in cap["mitre"]), cap["id"]


def test_mitre_confidence_depends_on_permission_backing():
    backed = finish({**clean_result(), "capabilities": [
        {"id": "sms_send", "label": "Send SMS", "tier": "high", "apis": ["sendTextMessage"],
         "status": "declared and used", "mitre": ["T1582"]}]})
    weak = finish({**clean_result(), "capabilities": [
        {"id": "sms_send", "label": "Send SMS", "tier": "high", "apis": ["sendTextMessage"],
         "status": "referenced only", "mitre": ["T1582"]}]})
    assert [t["confidence"] for t in map_to_mitre(backed) if t["technique_id"] == "T1582"] == ["medium"]
    assert [t["confidence"] for t in map_to_mitre(weak) if t["technique_id"] == "T1582"] == ["low"]
