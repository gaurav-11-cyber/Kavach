"""Signing certificate analysis."""
from datetime import datetime, timezone


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def analyze_certificates(apk):
    """Return signing scheme info and details of each signing certificate."""
    result = {
        "signed_v1": _safe(apk.is_signed_v1, False),
        "signed_v2": _safe(apk.is_signed_v2, False),
        "signed_v3": _safe(apk.is_signed_v3, False),
        "certificates": [],
    }
    now = datetime.now(timezone.utc)
    for cert in _safe(apk.get_certificates, []) or []:
        subject = str(_safe(lambda: cert.subject.human_friendly, "") or "")
        issuer = str(_safe(lambda: cert.issuer.human_friendly, "") or "")
        not_before = _safe(lambda: cert["tbs_certificate"]["validity"]["not_before"].native)
        not_after = _safe(lambda: cert["tbs_certificate"]["validity"]["not_after"].native)
        self_signed = _safe(lambda: cert.self_signed, "maybe")
        result["certificates"].append({
            "subject": subject,
            "issuer": issuer,
            "sha256": _safe(lambda: cert.sha256_fingerprint),
            "signature_algorithm": _safe(lambda: cert.signature_algo),
            "not_before": str(not_before) if not_before else None,
            "not_after": str(not_after) if not_after else None,
            "self_signed": self_signed in ("yes", "maybe") or subject == issuer,
            "debug_certificate": "android debug" in (subject + issuer).lower(),
            "expired": bool(not_after and not_after < now),
        })
    return result