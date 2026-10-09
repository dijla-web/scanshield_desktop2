"""فحص إعدادات SSL/TLS وشهادة الموقع - بدون أي أداة خارجية."""
import ssl
import socket
import datetime


def _check_protocol_supported(domain: str, port: int, min_ver, max_ver) -> bool:
    """يتأكد هل السيرفر يقبل نسخة بروتوكول معينة (نسخ قديمة = خطر أمني)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def run(domain: str, progress_callback=None) -> dict:
    port = 443
    findings = []

    # 1. جلب الشهادة والتحقق من تاريخ انتهائها
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                negotiated_version = ssock.version()

        expire_str = cert.get("notAfter")
        expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.datetime.utcnow()).days

        if days_left < 0:
            findings.append({"severity": "عالية", "issue": "شهادة SSL منتهية الصلاحية!"})
        elif days_left < 14:
            findings.append({"severity": "متوسطة", "issue": f"الشهادة تنتهي خلال {days_left} يوم"})

        issuer = dict(x[0] for x in cert.get("issuer", []))

    except ssl.SSLCertVerificationError as e:
        findings.append({"severity": "عالية", "issue": f"مشكلة بالشهادة: {e.verify_message}"})
        negotiated_version, issuer, days_left = "unknown", {}, None
    except Exception as e:
        return {"tool": "فحص SSL/TLS", "status": "failed", "error": str(e)}

    if progress_callback:
        progress_callback()

    # 2. التأكد من عدم قبول بروتوكولات قديمة غير آمنة (TLS 1.0/1.1)
    old_versions_to_test = []
    if hasattr(ssl.TLSVersion, "TLSv1"):
        old_versions_to_test.append(("TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1))
    if hasattr(ssl.TLSVersion, "TLSv1_1"):
        old_versions_to_test.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1))

    for label, min_v, max_v in old_versions_to_test:
        if _check_protocol_supported(domain, port, min_v, max_v):
            findings.append({"severity": "متوسطة", "issue": f"السيرفر يقبل اتصال بـ {label} (نسخة قديمة غير آمنة)"})
        if progress_callback:
            progress_callback()

    return {
        "tool": "فحص SSL/TLS",
        "status": "completed",
        "negotiated_protocol": negotiated_version,
        "certificate_issuer": issuer.get("organizationName", "غير معروف"),
        "days_until_expiry": days_left,
        "findings": findings,
        "summary": f"{len(findings)} ملاحظة" if findings else "لا توجد مشاكل واضحة بإعدادات SSL",
    }
