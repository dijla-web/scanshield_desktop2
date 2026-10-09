"""فحص رؤوس HTTP الأمنية - مواقع كثيرة ناسية حماية أساسية وتصير عرضة لهجمات شائعة."""
import requests

IMPORTANT_HEADERS = {
    "Strict-Transport-Security": "يحمي من هجمات تخفيض الاتصال لـ HTTP",
    "Content-Security-Policy": "يحمي من هجمات XSS بتقييد مصادر المحتوى",
    "X-Frame-Options": "يحمي من هجمات Clickjacking",
    "X-Content-Type-Options": "يمنع المتصفح من تخمين نوع الملف الخاطئ",
    "Referrer-Policy": "يتحكم بمعلومات التصفح المُرسلة لمواقع أخرى",
    "Permissions-Policy": "يحدد صلاحيات المتصفح (كاميرا، موقع...)",
}


def run(domain: str, progress_callback=None) -> dict:
    url = f"https://{domain}"
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        return {"tool": "رؤوس الأمان", "status": "failed", "error": str(e)}

    if progress_callback:
        progress_callback()

    missing = [{"name": h, "why_it_matters": why} for h, why in IMPORTANT_HEADERS.items() if h not in resp.headers]
    present = [h for h in IMPORTANT_HEADERS if h in resp.headers]
    server_banner = resp.headers.get("Server", "")

    return {
        "tool": "رؤوس الأمان",
        "status": "completed",
        "missing_headers": missing,
        "present_headers": present,
        "server_banner_exposed": bool(server_banner),
        "server_banner": server_banner,
        "summary": f"{len(missing)} رأس أمان ناقص من أصل {len(IMPORTANT_HEADERS)}",
    }
