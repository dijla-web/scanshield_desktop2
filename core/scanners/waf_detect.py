"""
يتحقق إذا الموقع محمي بجدار حماية (WAF) - عبر مقارنة استجابة طلب عادي
باستجابة طلب فيه نمط مشبوه بسيط (بدون أي محاولة استغلال فعلية، فقط
نص اختباري قياسي يُستخدم عالمياً لهذا الغرض تحديداً).
"""
import requests

WAF_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-iinfo": "Incapsula",
    "x-cdn": "CDN/WAF عام",
}

TEST_PAYLOAD = "?test=<script>alert(1)</script>"  # نص اختباري قياسي غير ضار، لا يُنفَّذ فعلياً


def run(domain: str, progress_callback=None) -> dict:
    base_url = f"https://{domain}"
    try:
        normal_resp = requests.get(base_url, timeout=10)
        if progress_callback:
            progress_callback()
        test_resp = requests.get(base_url + TEST_PAYLOAD, timeout=10)
        if progress_callback:
            progress_callback()
    except requests.RequestException as e:
        return {"tool": "كشف جدار الحماية", "status": "failed", "error": str(e)}

    detected_waf = None
    for header, name in WAF_SIGNATURES.items():
        if header in normal_resp.headers or header in test_resp.headers:
            detected_waf = name
            break

    blocked_test_request = test_resp.status_code in (403, 406, 419, 429, 503) and normal_resp.status_code == 200

    return {
        "tool": "كشف جدار الحماية",
        "status": "completed",
        "waf_detected": bool(detected_waf or blocked_test_request),
        "waf_name": detected_waf or ("جدار حماية غير معروف الاسم" if blocked_test_request else None),
        "summary": f"فيه جدار حماية ({detected_waf or 'غير محدد النوع'})" if (detected_waf or blocked_test_request) else "ما انكشف جدار حماية واضح",
    }
