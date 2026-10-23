"""Small fake objects shared by the tests."""
import os
from typing import Any


class FakeApk:
    """Stands in for an androguard APK object (no real APK needed)."""

    def __init__(self, dex=b"", files=None):
        self._dex = dex
        self._files = files or {}

    def get_all_dex(self):
        yield self._dex

    def get_files(self):
        return list(self._files)

    def get_file(self, name):
        return self._files[name]


def random_blob(size: int = 20_000) -> bytes:
    return os.urandom(size)


def perm(name: str, dangerous: bool = True) -> dict[str, Any]:
    return {"name": "android.permission." + name, "dangerous": dangerous}


def clean_result() -> dict[str, Any]:
    return {
        "permissions": [perm("VIBRATE", False)],
        "components": [
            {"type": "activity", "name": "Main", "exported": True, "permission": None},
            {"type": "receiver", "name": "x.Receiver", "exported": True,
             "permission": "android.permission.DUMP"},
        ],
        "iocs": {"urls": [], "ips": [], "domains": []},
        "certificate": {"signed_v1": True, "signed_v2": True, "signed_v3": False,
                        "certificates": [{"debug_certificate": False, "expired": False}]},
        "evasion": [],
        "libraries": [{"name": "AndroidX", "category": "framework"}],
    }


def trojan_result() -> dict[str, Any]:
    return {
        "permissions": [perm("READ_SMS"), perm("RECEIVE_SMS"), perm("INTERNET", False),
                        perm("BIND_ACCESSIBILITY_SERVICE"), perm("SYSTEM_ALERT_WINDOW"),
                        perm("REQUEST_INSTALL_PACKAGES"), perm("RECEIVE_BOOT_COMPLETED")],
        "components": [{"type": "service", "name": "a.B", "exported": True, "permission": None}],
        "iocs": {"urls": ["http://evil-c2.ru/gate.php"], "ips": ["185.220.101.4"], "domains": []},
        "certificate": {"signed_v1": True, "signed_v2": False, "signed_v3": False,
                        "certificates": [{"debug_certificate": True, "expired": False}]},
        "evasion": [
            {"indicator": "dynamic_code_loading", "severity": "medium", "description": "d",
             "evidence": ["dexclassloader"]},
            {"indicator": "emulator_detection", "severity": "high", "description": "e",
             "evidence": ["goldfish", "qemu", "ranchu"]},
            {"indicator": "encrypted_or_hidden_payload", "severity": "high", "description": "p",
             "evidence": ["assets/x.bin"]},
        ],
        "libraries": [],
    }