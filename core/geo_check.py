"""
تقييد استخدام البرنامج على الدول العربية فقط.

بما إن هذا تطبيق محلي بدون سيرفر، ما عندنا قاعدة بيانات محلية لعناوين IP
نقدر نرجع لها (هذي كبيرة الحجم وتحتاج تحديث دوري). البديل العملي: نسأل
خدمة مجانية بسيطة عبر الإنترنت "شنو دولة عنوان IP الحالي؟" - نفس
الإنترنت اللي أصلاً البرنامج يحتاجه عشان يسوي الفحص نفسه.

ما نرسل أي بيانات عن المستخدم لهذي الخدمة - بس نسألها "وين أنا؟"، ما
نعرّفها بأي شي ثاني.
"""
import requests

# دول الجامعة العربية (22 دولة) - عدّل هذي القائمة إذا تبي تضيق أو توسع النطاق
ALLOWED_COUNTRIES = {
    "DZ", "BH", "KM", "DJ", "EG", "IQ", "JO", "KW", "LB", "LY", "MR",
    "MA", "OM", "PS", "QA", "SA", "SO", "SD", "SY", "TN", "AE", "YE",
}


def get_country_code() -> str | None:
    """يرجع رمز الدولة الحالية (مثل IQ) أو None لو تعذر التحديد."""
    endpoints = [
        "https://ipapi.co/json/",
        "https://ipwho.is/",
    ]
    for url in endpoints:
        try:
            resp = requests.get(url, timeout=8)
            data = resp.json()
            code = data.get("country_code") or data.get("country")
            if code:
                return code.upper()
        except Exception:
            continue
    return None


def check_access() -> tuple[bool, str | None, str]:
    """يرجع (مسموح؟, رمز الدولة أو None, رسالة توضيحية)."""
    code = get_country_code()

    if code is None:
        return False, None, "تعذر تحديد موقعك الجغرافي. تأكد من اتصالك بالإنترنت وحاول مرة ثانية."

    if code in ALLOWED_COUNTRIES:
        return True, code, ""

    return False, code, f"هذا البرنامج متاح حالياً للدول العربية فقط. دولتك الحالية غير مدرجة ضمن القائمة ({code})."
