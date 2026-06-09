import ssl
import socket
import datetime
import logging
import asyncio
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _now_utc():
    return datetime.datetime.now(datetime.timezone.utc)

async def analyze_ssl(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme != "https":
        return {
            "available": False,
            "state": "not_https",
            "message": "URL does not use HTTPS",
        }

    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, _ssl_handshake, hostname, port)
        return result
    except ssl.SSLError as e:
        return {"available": False, "state": "ssl_error", "message": str(e)}
    except socket.timeout:
        return {"available": False, "state": "timeout", "message": "Connection timed out"}
    except Exception as e:
        return {"available": False, "state": "error", "message": str(e)}


def _ssl_handshake(hostname, port):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            protocol = get_protocol_version(ssock.version())
            cipher = ssock.cipher()
            return {
                "available": True,
                "protocol": protocol,
                "protocol_state": evaluate_protocol(protocol),
                "cipher": {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                },
                "certificate": parse_certificate(cert),
                "state": evaluate_ssl_state(cert, protocol),
            }

def get_protocol_version(version: str) -> str:
    return version

def evaluate_protocol(protocol: str) -> str:
    if "TLSv1.3" in protocol:
        return "secure"
    elif "TLSv1.2" in protocol:
        return "acceptable"
    elif "TLSv1.1" in protocol:
        return "weak"
    elif "TLSv1" in protocol or "SSLv" in protocol:
        return "insecure"
    return "unknown"

def parse_certificate(cert: dict) -> dict:
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    not_after = cert.get("notAfter", "")
    expiry_date = None
    days_until_expiry = None
    if not_after:
        try:
            expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
            days_until_expiry = (expiry_date - _now_utc()).days
        except Exception:
            pass

    serial_number = cert.get("serialNumber", "")
    if isinstance(serial_number, str):
        serial_number = serial_number.upper()

    return {
        "subject": subject,
        "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
        "common_name": subject.get("commonName", "Unknown"),
        "expiry_date": expiry_date.isoformat() if expiry_date else None,
        "days_until_expiry": days_until_expiry,
        "serial_number": serial_number,
        "is_expired": days_until_expiry is not None and days_until_expiry < 0,
        "is_expiring_soon": days_until_expiry is not None and 0 < days_until_expiry < 30,
    }

def evaluate_ssl_state(cert: dict, protocol: str) -> str:
    protocol_state = evaluate_protocol(protocol)
    if protocol_state == "insecure":
        return "insecure"

    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            if expiry < _now_utc():
                return "expired"
            days_left = (expiry - _now_utc()).days
            if days_left < 30:
                return "expiring_soon"
        except Exception:
            pass

    if protocol_state == "weak":
        return "weak"

    return "secure"
