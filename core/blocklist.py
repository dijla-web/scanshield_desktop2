import socket
import ipaddress

BLOCKED_DOMAIN_PATTERNS = [".gov", ".mil", "localhost", "127.0.0.1", "0.0.0.0"]

BLOCKED_IP_NETWORKS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128",
]


def is_domain_blocked(domain: str) -> tuple[bool, str]:
    domain_lower = domain.lower()
    for pattern in BLOCKED_DOMAIN_PATTERNS:
        if pattern in domain_lower:
            return True, f"النطاق يطابق نمط محظور: {pattern}"

    try:
        resolved_ip = socket.gethostbyname(domain)
        ip_obj = ipaddress.ip_address(resolved_ip)
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in ipaddress.ip_network(net):
                return True, "النطاق يشير إلى شبكة داخلية/محجوزة - غير مسموح"
    except (socket.gaierror, ValueError):
        return True, "تعذر تحليل النطاق إلى عنوان IP صالح - تأكد من كتابته صح"

    return False, ""
