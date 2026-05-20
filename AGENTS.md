# AGENTS.md

## Commands

### Backend (Python/FastAPI)
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend (React/pnpm)
```bash
cd frontend
pnpm install
pnpm dev
```

Frontend: `http://localhost:5173` | Backend: `http://localhost:8000`

## Architecture

- **Two independent projects**: `backend/` (FastAPI) and `frontend/` (Vite+React). No shared code or monorepo tooling.
- **Backend entrypoint**: `backend/main.py` — run via `uvicorn main:app`
- **Frontend entrypoint**: `frontend/src/main.jsx` → `App.jsx`
- **Vite proxies `/api`** to `http://localhost:8000` — no CORS issues in dev.

## Critical Backend Quirks

- **`sys.path.insert(0, ...)` in `main.py`**: Backend adds its own directory to `sys.path` so imports like `from config.settings import ...` work. Do NOT change import paths to relative or add `__init__.py` files without testing.
- **All endpoints accept `dict` not Pydantic models**: Request bodies are plain dicts with `request.get("url", "")`. The `routes/models.py` file defines Pydantic models but they are unused.
- **`detect_waf()` imports inside the function**: Circular import workaround in `routes/scan.py`. Keep this pattern if modifying.

## Data Files

- `backend/data/technologies.json` — Tech signatures for fingerprinting
- `backend/data/cves.json` — Local CVE database (20 entries)
- `backend/data/signatures.json` — WAF signatures, dangerous methods, sensitive files

## Scoring

Total score = `level1 * 0.3 + level2 * 0.4 + level3 * 0.3` (weighted average, 0-100).

## Security Constraints

- Private/internal IPs blocked in `utils/validators.py`
- Rate limiting: 10 req/min via `slowapi`
- Passive analysis only — no payloads sent

## No Test/Lint Config

No test framework, linter, or type checker is configured. If adding tests, use `pytest`. For linting, use `ruff` or `flake8`.
