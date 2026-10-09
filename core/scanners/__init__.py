from . import port_scan, tls_check, security_headers, tech_fingerprint, waf_detect, hidden_paths

ALL_SCANNERS = [
    ("port_scan", "فحص المنافذ المفتوحة", port_scan),
    ("tls_check", "فحص SSL/TLS", tls_check),
    ("security_headers", "رؤوس الأمان", security_headers),
    ("tech_fingerprint", "كشف التقنيات", tech_fingerprint),
    ("waf_detect", "كشف جدار الحماية", waf_detect),
    ("hidden_paths", "ملفات ومسارات حساسة", hidden_paths),
]
