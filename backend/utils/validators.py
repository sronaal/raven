import json
import ipaddress
from urllib.parse import urlparse
from config.settings import BLOCKED_IP_RANGES, ALLOWED_SCHEMES

def validate_url(url: str) -> tuple[bool, str]:
    if not url:
        return False, "URL is required"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Only HTTP/HTTPS schemes allowed. Got: {parsed.scheme}"

    if not parsed.hostname:
        return False, "Hostname is required"

    if is_private_ip(parsed.hostname):
        return False, "Scanning private/internal IPs is not allowed"

    return True, "Valid URL"

def is_private_ip(hostname: str) -> bool:
    try:
        import socket
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        for range_str in BLOCKED_IP_RANGES:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except Exception:
        return False

def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    return parsed.geturl().rstrip("/")
