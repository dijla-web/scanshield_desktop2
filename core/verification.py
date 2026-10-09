import secrets
import requests
import dns.resolver

VERIFICATION_PATH = "/.well-known/scanshield-verify.txt"


def generate_token() -> str:
    return "scanshield-verify-" + secrets.token_hex(16)


def check_file_verification(domain: str, token: str) -> bool:
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}{VERIFICATION_PATH}", timeout=10)
            if resp.status_code == 200 and token in resp.text:
                return True
        except requests.RequestException:
            continue
    return False


def check_dns_verification(domain: str, token: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt_value = b"".join(rdata.strings).decode(errors="ignore")
            if token in txt_value:
                return True
    except Exception:
        return False
    return False


def check_verification(domain: str, token: str, method: str) -> bool:
    if method == "file":
        return check_file_verification(domain, token)
    elif method == "dns":
        return check_dns_verification(domain, token)
    return False
