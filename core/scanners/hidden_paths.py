"""
يتحقق من وجود ملفات/مجلدات حساسة منسية بأسماء شائعة جداً (نسخ احتياطية،
ملفات إعدادات، لوحات إدارة) - فحص غير مؤذي (طلبات GET عادية بس)،
بطيء مقصوداً (تأخير بسيط بين كل طلب) حتى ما يثقل على السيرفر المستهدف.
"""
import time
import requests

COMMON_PATHS = [
    ".env", ".git/config", "wp-admin/", "admin/", "backup.zip", "backup.sql",
    ".htaccess", "config.php.bak", "phpinfo.php", ".DS_Store", "robots.txt",
    "sitemap.xml", "server-status", ".well-known/security.txt", "api/",
    "swagger.json", "swagger-ui.html", ".git/HEAD", "composer.json",
    "package.json", "web.config", "error_log", "debug.log",
]

DELAY_BETWEEN_REQUESTS = 0.3


def run(domain: str, progress_callback=None) -> dict:
    base_url = f"https://{domain}"
    found = []

    for path in COMMON_PATHS:
        try:
            resp = requests.get(f"{base_url}/{path}", timeout=6, allow_redirects=False)
            if resp.status_code in (200, 301, 302):
                found.append({"path": path, "status_code": resp.status_code})
        except requests.RequestException:
            pass
        time.sleep(DELAY_BETWEEN_REQUESTS)
        if progress_callback:
            progress_callback()

    return {
        "tool": "ملفات ومسارات حساسة",
        "status": "completed",
        "found": found,
        "summary": f"{len(found)} مسار ظهر متاح من أصل {len(COMMON_PATHS)} تم فحصها",
    }
