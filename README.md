# URL Security Scanner

Multi-level web URL security analysis tool for educational purposes and authorized penetration testing.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12 + FastAPI 0.104 + SlowAPI + httpx |
| **Frontend** | React 18 + Vite 5 + Tailwind CSS 3.4 |
| **WebSocket** | FastAPI WebSocket (real-time scan progress) |
| **Infra** | Docker Compose (backend + frontend) |

## Architecture

Two independent projects — no monorepo tooling:

```
scanner_intelligent/
├── backend/                  # FastAPI application
│   ├── main.py               # Entrypoint
│   ├── config/settings.py    # Configuration
│   ├── routes/               # API handlers
│   │   ├── scan.py           # Scanner endpoints
│   │   ├── crawler.py        # Crawling + extended analysis
│   │   ├── history.py        # Scan history & PDF report
│   │   └── websocket.py      # Real-time progress
│   ├── services/             # Business logic
│   ├── utils/                # Validators
│   └── data/                 # Signatures, CVE DB, fingerprints
├── frontend/                 # Vite + React application
│   └── src/
│       ├── components/       # React components
│       └── utils/api.js      # API client
├── docker-compose.yml        # Backend + frontend orchestration
└── .env.example              # Configuration template
```

The frontend proxies `/api` requests to the backend at `http://localhost:8000` (no CORS issues in dev).

## Features

### Level 1 — Reconnaissance & Fingerprinting
- Server detection and version identification
- Technology stack fingerprinting (languages, frameworks, CMS, libraries)
- HTTP security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- Security misconfiguration detection
- Mozilla Observatory-style grading

### Level 2 — Vulnerability Analysis
- Local CVE database matching (20+ entries)
- External CVE fetching (NVD/NIST API)
- SSL/TLS certificate analysis (protocol version, cipher, expiry)
- WAF detection (Cloudflare, ModSecurity, etc.)
- Known vulnerability pattern matching

### Level 3 — Parameter & Attack Vector Analysis
- SQL injection vector detection
- XSS reflection analysis
- Path traversal identification
- SSRF and open redirect checks
- CSRF protection analysis
- Rate limiting detection

### Additional Modules
- **Crawler** — recursive site crawling with depth/page limits
- **OWASP Top 10** — automated OWASP risk assessment
- **API Discovery** — endpoint enumeration from HTML/JS
- **Dependency Checker** — known vulnerable library detection
- **Attack Surface Mapping** — consolidated risk visualization
- **Compliance Checker** — PCI-DSS, GDPR, HIPAA readiness
- **Redirect Chain Analysis** — full redirect path tracing
- **Subdomain Enumeration** — passive subdomain discovery
- **Robots.txt & Sitemap** — policy and sitemap extraction
- **Cookie Analysis** — security attributes per cookie
- **Batch Scan** — scan up to 20 URLs in parallel
- **History & Comparison** — scan persistence, diff between scans
- **PDF Report** — export scan results as PDF

## Scoring

```
total_score = level1_score * 0.3 + level2_score * 0.4 + level3_score * 0.3
```

Weighted average (0–100) favoring vulnerability analysis.

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

Open `http://localhost:5173` in your browser.

### Docker

```bash
docker compose up --build
```

## Configuration

Copy `.env.example` to `.env` and adjust:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-in-production` | App secret key |
| `EXTERNAL_API_ENABLED` | `true` | Enable external CVE/NVD lookups |
| `MAX_BODY_SIZE` | `100000` | Max HTTP body size to analyze (bytes) |

## API Endpoints

### Scanner

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan/full` | Full 3-level scan |
| `POST` | `/api/scan/level1` | Level 1 only (fingerprinting) |
| `POST` | `/api/scan/level2` | Level 2 only (vulnerabilities) |
| `POST` | `/api/scan/level3` | Level 3 only (parameters) |
| `POST` | `/api/scan/redirects` | Redirect chain analysis |
| `POST` | `/api/scan/subdomains` | Subdomain enumeration |
| `POST` | `/api/scan/robots` | Robots.txt & sitemap analysis |
| `POST` | `/api/scan/batch` | Batch scan (up to 20 URLs) |
| `POST` | `/api/scan/cookies` | Cookie security analysis |
| `POST` | `/api/scan/grade` | Mozilla Observatory grading |

### Crawler & Extended

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/crawl` | Recursive site crawling |
| `POST` | `/api/scan/owasp` | OWASP Top 10 assessment |
| `POST` | `/api/discover` | API endpoint discovery |
| `POST` | `/api/dependencies` | Dependency vulnerability check |
| `POST` | `/api/compliance` | Compliance check (PCI/GDPR/HIPAA) |
| `POST` | `/api/surface` | Attack surface mapping |

### History & Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/scans` | List past scans |
| `GET` | `/api/scans/:id` | Get scan details |
| `DELETE` | `/api/scans/:id` | Delete a scan |
| `GET` | `/api/scans/:id/report` | Download PDF report |
| `GET` | `/api/scans/compare` | Compare two scans |
| `GET` | `/api/stats` | Scan statistics |

### WebSocket

| Path | Description |
|------|-------------|
| `WS` | `/ws/{client_id}` | Real-time scan progress updates |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Service health check |

## Security

- **Rate limiting**: 10 requests/minute per IP (via SlowAPI)
- **Private IP blocking**: RFC 1918, loopback, and reserved ranges blocked
- **DNS rebinding protection**: Resolved IPs validated against blocklist
- **Passive analysis only**: No payloads or exploitation sent
- **All scans logged**: Full audit trail with client IP and timestamp

## Disclaimer

This tool is for educational purposes and authorized penetration testing only. Only scan websites you have explicit permission to test. Unauthorized scanning may violate applicable laws.
