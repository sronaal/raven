# URL Security Scanner

Multi-level web URL security analysis tool for educational purposes and authorized penetration testing.

## Features

- **Level 1 - Reconnaissance & Fingerprinting**: Server detection, technology identification, HTTP header analysis, security misconfiguration detection
- **Level 2 - Vulnerability Analysis**: CVE database lookup, SSL/TLS certificate analysis, WAF detection, known vulnerability matching
- **Level 3 - Parameter & Attack Vector Analysis**: SQL injection vectors, XSS detection, path traversal, SSRF, open redirect, CSRF analysis

## Tech Stack

- **Backend**: Python + FastAPI
- **Frontend**: React + Vite + Tailwind CSS
- **HTTP Client**: httpx (backend), axios (frontend)

## Quick Start

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
pnpm install
pnpm dev
```

The frontend runs on `http://localhost:5173` and proxies API requests to the backend at `http://localhost:8000`.

## API Endpoints

- `POST /api/scan/full` - Full 3-level scan
- `POST /api/scan/level1` - Level 1 only (fingerprinting)
- `POST /api/scan/level2` - Level 2 only (vulnerabilities)
- `POST /api/scan/level3` - Level 3 only (parameters)
- `GET /api/health` - Health check

## Security

- Rate limiting: 10 requests/minute per IP
- Private IP ranges blocked
- Passive analysis only (no active exploitation)
- All scans logged

## Disclaimer

This tool is for educational purposes and authorized penetration testing only. Only scan websites you have explicit permission to test.
