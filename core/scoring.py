"""
يحوّل نتائج كل الفحوصات لدرجة واحدة مفهومة (A إلى F) - بدل ما المستخدم
يقرا تفاصيل تقنية كثيرة، يشوف رقم/حرف واحد يلخص وضع موقعه.
"""

RISKY_PORTS = {21: "FTP", 23: "Telnet", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
               6379: "Redis", 27017: "MongoDB", 445: "SMB"}

SENSITIVE_PATH_WEIGHT = {
    ".env": 15, ".git/config": 15, ".git/HEAD": 12, "backup.sql": 12, "backup.zip": 10,
    "config.php.bak": 12, "web.config": 8, "error_log": 6, "debug.log": 6,
}


def calculate(results: dict[str, dict]) -> dict:
    score = 100
    reasons = []

    port_result = results.get("port_scan", {})
    for p in port_result.get("open_ports", []):
        if p["port"] in RISKY_PORTS:
            score -= 8
            reasons.append(f"منفذ حساس مفتوح: {RISKY_PORTS[p['port']]} ({p['port']})")

    tls_result = results.get("tls_check", {})
    for f in tls_result.get("findings", []):
        deduction = 15 if f["severity"] == "عالية" else 7
        score -= deduction
        reasons.append(f"SSL: {f['issue']}")

    headers_result = results.get("security_headers", {})
    missing = headers_result.get("missing_headers", [])
    score -= len(missing) * 4
    if len(missing) >= 4:
        reasons.append(f"{len(missing)} رؤوس أمان أساسية ناقصة")

    waf_result = results.get("waf_detect", {})
    if waf_result.get("status") == "completed" and not waf_result.get("waf_detected"):
        score -= 5
        reasons.append("ما فيه جدار حماية (WAF) واضح")

    hidden_result = results.get("hidden_paths", {})
    for item in hidden_result.get("found", []):
        weight = SENSITIVE_PATH_WEIGHT.get(item["path"], 4)
        score -= weight
        reasons.append(f"مسار حساس متاح: /{item['path']}")

    score = max(0, min(100, score))

    if score >= 90:
        grade, color, label = "A", "#52B788", "ممتاز"
    elif score >= 75:
        grade, color, label = "B", "#8FBF6E", "جيد"
    elif score >= 60:
        grade, color, label = "C", "#E8B33D", "متوسط - يحتاج تحسين"
    elif score >= 40:
        grade, color, label = "D", "#E07A3F", "ضعيف - انتبه"
    else:
        grade, color, label = "F", "#E2634F", "خطر - يحتاج إصلاح فوري"

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "label": label,
        "top_reasons": reasons[:6],
    }
