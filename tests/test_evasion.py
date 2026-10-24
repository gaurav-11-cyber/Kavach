from analyzer.evasion import detect_evasion
from tests.helpers import FakeApk, random_blob


def by_id(findings):
    return {f["indicator"]: f for f in findings}


def test_clean_code_has_no_findings():
    assert detect_evasion(FakeApk(dex=b"Lcom/example/Foo; Lcom/example/Bar;")) == []


def test_dynamic_code_loading_detected():
    f = by_id(detect_evasion(FakeApk(dex=b"Ldalvik/system/DexClassLoader;")))
    assert f["dynamic_code_loading"]["severity"] == "medium"


def test_one_emulator_string_is_only_low():
    f = by_id(detect_evasion(FakeApk(dex=b"sdk_gphone")))
    assert f["emulator_detection"]["severity"] == "low"


def test_three_emulator_strings_are_high():
    f = by_id(detect_evasion(FakeApk(dex=b"goldfish qemu ranchu")))
    assert f["emulator_detection"]["severity"] == "high"


def test_two_hooking_strings_stay_low():
    f = by_id(detect_evasion(FakeApk(dex=b"frida xposed")))
    assert f["hooking_framework_detection"]["severity"] == "low"


def test_reflection_is_informational_only():
    f = by_id(detect_evasion(FakeApk(dex=b"Ljava/lang/reflect/Method;")))
    assert f["reflection"]["severity"] == "info"


def test_high_entropy_asset_is_flagged():
    apk = FakeApk(files={"assets/payload.bin": random_blob()})
    assert "encrypted_or_hidden_payload" in by_id(detect_evasion(apk))


def test_baseline_profile_is_ignored():
    """Regression: ART baseline profiles are high entropy but harmless."""
    apk = FakeApk(files={"assets/dexopt/baseline.prof": random_blob()})
    assert "encrypted_or_hidden_payload" not in by_id(detect_evasion(apk))


def test_images_are_ignored():
    apk = FakeApk(files={"assets/logo.png": random_blob()})
    assert detect_evasion(apk) == []


def test_name_obfuscation_needs_many_short_class_names():
    short = b" ".join(b"Lab/cd;" for _ in range(200))
    f = by_id(detect_evasion(FakeApk(dex=short)))
    assert f["name_obfuscation"]["severity"] == "low"
    normal = b" ".join(b"Lcom/example/Thing%d;" % i for i in range(200))
    assert "name_obfuscation" not in by_id(detect_evasion(FakeApk(dex=normal)))