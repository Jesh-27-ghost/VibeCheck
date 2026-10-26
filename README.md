# 🛡️ VibeCheck — AI Security Reviewer for Vibe-Coded Websites

> **Upload your source code. Get actionable security findings. Copy the AI repair prompt. Rescan to verify the fix.**

VibeCheck is an open-source, deterministic security scanner built for the "vibe coding" era. It accepts website source code (as ZIP archives), detects high-impact vulnerabilities — exposed secrets, permissive CORS, auth flaws, client-side credential leaks — and generates a single consolidated AI repair prompt you can paste directly into your coding assistant to fix everything at once.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **🔍 Deterministic Security Scanning** | AST-aware and regex-based rules detect secrets, CORS misconfigurations, XSS sinks, auth flaws, and more — without executing your code. |
| **🔐 Secret Masking** | All discovered credentials are automatically redacted before they appear in any output. |
| **🤖 AI Repair Prompt** | A single consolidated prompt is generated from all findings — copy-paste it into ChatGPT, Gemini, Copilot, or any AI assistant to fix your code. |
| **🔄 Rescan & Comparison** | Submit corrected code against a baseline scan for a verified before/after diff showing resolved, remaining, and new issues. |
| **⚡ 1-Click Demo** | Bundled vulnerable and corrected sample projects let you experience the full scan → fix → rescan loop instantly. |
| **🧱 Sandboxed Intake** | ZIP uploads are validated for size limits, zip-slip attacks, zip bombs, symlinks, executables, and directory traversal — your code is never executed. |
| **🌐 Modern Web Frontend** | A polished single-page dashboard to upload, review findings, copy repair prompts, and compare rescans visually. |

---

## 🏗️ Architecture

```
VibeCheck/
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── main.py           # App entrypoint, CORS, health endpoint
│   │   ├── api/router.py     # REST endpoints (scan, rescan, comparison, demo)
│   │   ├── intake/           # ZIP upload validation, sandboxing, manifest
│   │   └── schemas/          # Pydantic models (scan, finding, comparison, health)
│   ├── scanners/             # Deterministic rule engine, pattern rules, secret masking
│   ├── remediation/          # AI repair prompt generator
│   ├── comparison/           # Baseline vs rescan diffing & fingerprinting
│   └── tests/                # Automated test suite (pytest)
├── frontend/                 # Static SPA (HTML/CSS/JS)
│   ├── index.html
│   ├── css/styles.css
│   └── js/app.js
├── contracts/                # JSON schemas and API examples
├── samples/                  # Bundled demo fixtures
│   ├── vulnerable/           # Deliberately vulnerable sample project
│   └── corrected/            # Fixed version for rescan comparison
├── scripts/                  # Phase checkpoint runner & dashboard CLI
├── requirements.txt
├── pytest.ini
├── .env.example
└── CHECKPOINTS.md            # Phase gate specifications & evidence
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+** (tested on Python 3.14)
- `pip` package manager

### 1. Clone & Setup

```bash
git clone https://github.com/Jesh-27-ghost/VibeCheck.git
cd VibeCheck
```

Create and activate a virtual environment:

```bash
# Windows (PowerShell)
py -m venv .venv
.venv\Scripts\Activate.ps1

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Copy the environment template:

```bash
# Windows
Copy-Item .env.example .env

# macOS / Linux
cp .env.example .env
```

### 2. Run the API Server

```bash
# Windows
py -m uvicorn backend.app.main:app --reload --port 8000

# macOS / Linux
uvicorn backend.app.main:app --reload --port 8000
```

The app is now live:

| Endpoint | URL |
|---|---|
| 🏠 Frontend Dashboard | [`http://localhost:8000`](http://localhost:8000) |
| 💚 Health Check | [`http://localhost:8000/health`](http://localhost:8000/health) |
| 📤 Scan Upload | `POST http://localhost:8000/api/v1/scans` |
| 📖 Interactive API Docs | [`http://localhost:8000/docs`](http://localhost:8000/docs) |
| 📘 ReDoc | [`http://localhost:8000/redoc`](http://localhost:8000/redoc) |

### 3. Run Tests

```bash
# Full test suite
py -m pytest

# With coverage
py -m pytest --cov=backend
```

---

## 📡 API Reference

### `POST /api/v1/scans` — Upload & Scan

Upload a `.zip` archive of your website source code for security analysis.

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -F "file=@my-website.zip"
```

**Response** (`201 Created`):

```json
{
  "scan_id": "scan_84532e36dd9f",
  "status": "completed",
  "project": "my-website",
  "coverage": {
    "files_scanned": 12,
    "total_lines": 850,
    "rules_evaluated": 10,
    "skipped_files": []
  },
  "findings": [
    {
      "rule_id": "SECRET_001",
      "title": "Hardcoded API Key / Token",
      "severity": "high",
      "location": { "file_path": "config.js", "line_start": 14 }
    }
  ],
  "repair_prompt": "You are a senior security engineer. Fix the following...",
  "limitations": []
}
```

### `GET /api/v1/scans/{scan_id}` — Retrieve Scan

```bash
curl http://localhost:8000/api/v1/scans/scan_84532e36dd9f
```

### `POST /api/v1/scans/{scan_id}/rescan` — Rescan & Compare

Upload corrected code against a baseline scan to see what was fixed:

```bash
curl -X POST http://localhost:8000/api/v1/scans/scan_84532e36dd9f/rescan \
  -F "file=@my-website-fixed.zip"
```

**Response** includes `resolved_by_checks`, `still_present`, `new`, and `not_verified` categories with a summary diff.

### `POST /api/v1/demo/scan-sample` — 1-Click Demo

Run a scan on the bundled vulnerable sample without uploading anything:

```bash
curl -X POST "http://localhost:8000/api/v1/demo/scan-sample?sample_type=vulnerable"
```

### `POST /api/v1/demo/rescan-sample/{scan_id}` — 1-Click Rescan Demo

Rescan with the corrected sample against a baseline:

```bash
curl -X POST http://localhost:8000/api/v1/demo/rescan-sample/scan_84532e36dd9f
```

---

## 🔒 Safety Controls

VibeCheck never executes, imports, or installs any uploaded code. All analysis is purely static.

| Guard | Default |
|---|---|
| Max compressed upload | 25 MB |
| Max archive entries | 500 |
| Max total uncompressed | 50 MB |
| Max individual file | 5 MB |
| Zip-slip protection | ✅ Rejects `../`, absolute paths, drive letters |
| Symlink / FIFO / device nodes | ✅ Rejected |
| Binary executables | ✅ Rejected (`.exe`, `.dll`, `.so`, `.bin`, etc.) |
| Excluded directories | `.git`, `node_modules`, `.venv`, `__pycache__` |
| Isolated workspace | Each scan gets `temp_scans/<scan_id>/source` |
| Failure cleanup | Errors wipe the workspace immediately |

---

## 🧪 Security Rules

VibeCheck ships with deterministic rules covering:

| Category | Examples |
|---|---|
| **Exposed Secrets** | API keys, tokens, passwords, database URIs hardcoded in source |
| **CORS Misconfig** | Wildcard `Access-Control-Allow-Origin: *` with credentials |
| **Auth Flaws** | Disabled CSRF protection, missing auth middleware, permissive session configs |
| **XSS / Injection** | `innerHTML` assignments, `eval()` usage, unsanitized template interpolation |
| **Client-side Leaks** | Credentials in JavaScript bundles, localStorage token storage |

All secret values are **automatically masked** in findings output.

---

## 📋 Phase Implementation Status

| Phase | Gate | Status | Description |
|---|---|---|---|
| **1** | Foundation & Contracts | ✅ PASSED | Core schemas, JSON contracts, `/health`, baseline tests |
| **2** | Secure Source Code Intake | ✅ PASSED | ZIP upload, archive safety, sandboxing, manifest |
| **3** | Security Scanner Integration | ✅ PASSED | AST/regex rules, line-grounded evidence, secret masking |
| **4** | Findings & Remediation | ✅ PASSED | Deduplication, consolidated AI repair prompt synthesis |
| **5** | Rescan Comparison | ✅ PASSED | Baseline persistence, rescan diffing, state transitions |
| **6** | End-to-End MVP | ✅ PASSED | Full user journey from submission to rescan diff |
| **7** | Release Gate | ✅ PASSED | Release qualification audit |

See [CHECKPOINTS.md](./CHECKPOINTS.md) for detailed gate criteria and evidence.

---

## 🖥️ Phase Checkpoint CLI

VibeCheck includes a deterministic checkpoint runner for verifying phase gates:

```bash
# Run all-phase dashboard
py scripts/phase_check.py --all

# Run individual phase gate
py scripts/phase_check.py 1   # Foundation
py scripts/phase_check.py 3   # Scanner Integration
py scripts/phase_check.py 7   # Release Gate
```

**Result definitions**: `[PASS]` = assertions passed · `[FAIL]` = assertion failure · `[NOT IMPLEMENTED]` = not yet built · `[BLOCKED]` = prerequisites failing

---

## 🛠️ Tech Stack

- **Backend**: Python · FastAPI · Pydantic · Uvicorn
- **Frontend**: HTML5 · CSS3 · Vanilla JavaScript
- **Testing**: pytest · httpx (async test client)
- **Fonts**: Plus Jakarta Sans · JetBrains Mono

---

## 📄 License

This project is open source. See [LICENSE](./LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run the test suite (`py -m pytest`)
4. Commit your changes (`git commit -m 'feat: add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

---

<p align="center">
  Built with 🛡️ by <a href="https://github.com/Jesh-27-ghost">Jesh</a>
</p>