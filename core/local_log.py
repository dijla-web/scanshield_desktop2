"""
سجل محلي بسيط - يُحفظ بجهاز المستخدم نفسه فقط، ما يروح لأي مكان ثاني.
هذا "دليل المستخدم الشخصي" إنه وافق وتحقق قبل كل فحص - يخصه هو لحاله.
"""
import json
import os
import datetime
from pathlib import Path

APP_DATA_DIR = Path(os.path.expanduser("~")) / "ScanShieldData"
LOG_FILE = APP_DATA_DIR / "scan_log.jsonl"

MAX_SCANS_PER_DAY = 5


def _ensure_dir():
    APP_DATA_DIR.mkdir(exist_ok=True)


def record_scan(domain: str, verification_method: str, consent_version: str):
    _ensure_dir()
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "domain": domain,
        "verification_method": verification_method,
        "consent_version": consent_version,
        "windows_username": os.getlogin() if hasattr(os, "getlogin") else "unknown",
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def read_all_scans():
    if not LOG_FILE.exists():
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def scans_today_count() -> int:
    today = datetime.date.today().isoformat()
    return sum(1 for s in read_all_scans() if s["timestamp"].startswith(today))


def can_scan_today() -> tuple[bool, int]:
    count = scans_today_count()
    return count < MAX_SCANS_PER_DAY, max(0, MAX_SCANS_PER_DAY - count)
