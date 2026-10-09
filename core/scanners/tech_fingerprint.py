"""كشف التقنيات المستخدمة بالموقع - يساعد بمعرفة هل فيه نسخة قديمة معروفة بثغرات."""
import re
import requests

SIGNATURES = [
    ("WordPress", [r"wp-content", r"wp-includes", r'name="generator"\s+content="WordPress']),
    ("Joomla", [r"/media/jui/", r'name="generator"\s+content="Joomla']),
    ("Drupal", [r"Drupal.settings", r"/sites/default/files/"]),
    ("Shopify", [r"cdn\.shopify\.com", r"Shopify\.theme"]),
    ("Laravel", [r"laravel_session"]),
    ("Django", [r"csrftoken"]),
    ("React", [r"__REACT_DEVTOOLS", r'id="root"']),
    ("Next.js", [r"__NEXT_DATA__"]),
]


def run(domain: str, progress_callback=None) -> dict:
    url = f"https://{domain}"
    try:
        resp = requests.get(url, timeout=10)
    except requests.RequestException as e:
        return {"tool": "كشف التقنيات", "status": "failed", "error": str(e)}

    if progress_callback:
        progress_callback()

    html = resp.text
    detected = []
    for tech_name, patterns in SIGNATURES:
        if any(re.search(p, html, re.IGNORECASE) for p in patterns):
            detected.append(tech_name)

    server = resp.headers.get("Server", "غير معلن")
    powered_by = resp.headers.get("X-Powered-By", "")

    return {
        "tool": "كشف التقنيات",
        "status": "completed",
        "detected_technologies": detected or ["لم يتم التعرف على تقنية محددة"],
        "server_header": server,
        "powered_by_header": powered_by,
        "summary": f"تقنيات مكتشفة: {', '.join(detected)}" if detected else "ما انكشفت تقنية واضحة",
    }
