"""Comprehensive End-to-End integration test suite for Phase 6 MVP User Journey."""

import io
import zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def create_zip_bytes(files: dict) -> bytes:
    """Helper to build an in-memory zip archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf.getvalue()


@pytest.fixture
def client():
    return TestClient(app)


def test_e2e_health_check_readiness(client):
    """E2E Step 1: GET /health returns service readiness and version."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["ready"] is True
    assert "version" in data


def test_e2e_complete_scan_remediation_rescan_journey(client):
    """Complete E2E user journey:

    1. User uploads vulnerable project archive.
    2. Scanner identifies vulnerabilities with 100% secret masking.
    3. User retrieves consolidated AI repair prompt.
    4. User submits corrected project archive for rescan.
    5. Comparison engine verifies resolved findings vs persistent vs new.
    """
    # 1. Vulnerable code submission
    vuln_zip = create_zip_bytes(
        {
            "src/app.py": (
                'OPENAI_API_KEY = "sk-test-abc123xyz456verylongfakekey9876"\n'
                'DB_PASSWORD = "super_secret_password_123"\n'
                'DATABASE_URL = "postgresql://admin:mypassword123@localhost:5432/mydb"\n'
                '\n'
                'def run_query(user_id):\n'
                '    import sqlite3\n'
                '    conn = sqlite3.connect("db.sqlite")\n'
                '    c = conn.cursor()\n'
                '    c.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
                '    return c.fetchone()\n'
                '\n'
                'def calc(expr):\n'
                '    return eval(expr)\n'
            ),
            "README.md": "# Vulnerable Demo App\n",
        }
    )

    scan_res = client.post(
        "/api/v1/scans",
        files={"file": ("vulnerable_app.zip", vuln_zip, "application/zip")},
    )
    assert scan_res.status_code == 201
    scan_data = scan_res.json()

    base_scan_id = scan_data["scan_id"]
    assert base_scan_id.startswith("scan_") or len(base_scan_id) > 5
    assert scan_data["status"] == "completed"

    findings = scan_data["findings"]
    assert len(findings) > 0

    # Ensure no raw secrets are in findings or evidence
    raw_secrets = [
        "sk-test-abc123xyz456verylongfakekey9876",
        "super_secret_password_123",
        "mypassword123",
    ]
    for f in findings:
        for secret in raw_secrets:
            assert secret not in str(f["evidence"]), f"Raw secret leaked in finding {f['id']}"

    # 2. Retrieve scan report via GET
    get_res = client.get(f"/api/v1/scans/{base_scan_id}")
    assert get_res.status_code == 200
    report_data = get_res.json()
    assert report_data["scan_id"] == base_scan_id

    # 3. Verify usable AI repair prompt
    repair_prompt = report_data.get("repair_prompt")
    assert repair_prompt is not None and len(repair_prompt) > 50
    for secret in raw_secrets:
        assert secret not in repair_prompt, "Raw secret leaked in repair prompt"
    # Prompt references finding IDs
    assert any(f["id"] in repair_prompt for f in findings)

    # 4. User submits corrected code for rescan
    corrected_zip = create_zip_bytes(
        {
            "src/app.py": (
                'import os\n'
                'import sqlite3\n'
                '\n'
                'OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")\n'
                'DB_PASSWORD = os.environ.get("DB_PASSWORD")\n'
                'DATABASE_URL = os.environ.get("DATABASE_URL")\n'
                '\n'
                'def run_query(user_id):\n'
                '    conn = sqlite3.connect("db.sqlite")\n'
                '    c = conn.cursor()\n'
                '    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
                '    return c.fetchone()\n'
                '\n'
                'def calc(expr):\n'
                '    import ast\n'
                '    return ast.literal_eval(expr)\n'
            ),
            "README.md": "# Corrected App\n",
        }
    )

    rescan_res = client.post(
        f"/api/v1/scans/{base_scan_id}/rescan",
        files={"file": ("corrected_app.zip", corrected_zip, "application/zip")},
    )
    assert rescan_res.status_code == 201
    comp_data = rescan_res.json()

    assert comp_data["base_scan_id"] == base_scan_id
    new_scan_id = comp_data["rescan_id"]
    assert new_scan_id != base_scan_id

    # 5. Check comparison verification categories
    resolved = comp_data["resolved_by_checks"]
    assert len(resolved) > 0, "Expected resolved vulnerabilities in corrected rescan"
    assert comp_data["summary"]["resolved_count"] == len(resolved)

    # 6. Verify GET comparison endpoint
    get_comp = client.get(f"/api/v1/scans/{base_scan_id}/comparison/{new_scan_id}")
    assert get_comp.status_code == 200
    retrieved_comp = get_comp.json()
    assert retrieved_comp["summary"]["resolved_count"] == len(resolved)


def test_e2e_error_handling_and_status_codes(client):
    """Verify HTTP status codes for edge and error conditions."""
    # 1. Invalid file upload (not a zip)
    res = client.post(
        "/api/v1/scans",
        files={"file": ("malicious.exe", b"MZ\x90\x00\x03\x00", "application/x-dosexec")},
    )
    assert res.status_code in (400, 415, 422)

    # 2. Non-existent scan ID lookup
    res = client.get("/api/v1/scans/non-existent-scan-id-xyz")
    assert res.status_code == 404

    # 3. Rescan on non-existent baseline scan
    zip_bytes = create_zip_bytes({"test.py": "x = 1\n"})
    res = client.post(
        "/api/v1/scans/non-existent-scan-id-xyz/rescan",
        files={"file": ("test.zip", zip_bytes, "application/zip")},
    )
    assert res.status_code == 404

    # 4. Comparison on missing scans
    res = client.get("/api/v1/scans/missing-1/comparison/missing-2")
    assert res.status_code == 404
