"""فحص منافذ خفيف وسريع - بدون أي أداة خارجية، فقط مكتبة socket المدمجة بـ Python."""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _check_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=2):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run(domain: str, progress_callback=None) -> dict:
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"tool": "فحص المنافذ", "status": "failed", "error": "تعذر تحليل الدومين"}

    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check_port, ip, port): port for port in COMMON_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append({"port": port, "service": COMMON_PORTS[port]})
            if progress_callback:
                progress_callback()

    open_ports.sort(key=lambda x: x["port"])
    return {
        "tool": "فحص المنافذ",
        "status": "completed",
        "resolved_ip": ip,
        "open_ports": open_ports,
        "summary": f"{len(open_ports)} منفذ مفتوح من أصل {len(COMMON_PORTS)} تم فحصها",
    }
