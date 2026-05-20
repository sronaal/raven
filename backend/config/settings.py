import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

RATE_LIMIT = "10/minute"

SCAN_TIMEOUT = 30

ALLOWED_SCHEMES = ["http", "https"]

BLOCKED_IP_RANGES = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

USER_AGENT = "URLSecurityScanner/1.0 (Educational Security Tool)"

EXTERNAL_API_ENABLED = os.getenv("EXTERNAL_API_ENABLED", "true").lower() == "true"

CRT_SH_API = "https://crt.sh/"

CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
