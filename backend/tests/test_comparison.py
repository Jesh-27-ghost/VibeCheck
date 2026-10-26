"""Comprehensive unit and integration test suite for Phase 5 Rescan Comparison & Verification."""

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.comparison import (
    ComparisonResult,
    ScanComparator,
    compare_scans,
    compute_finding_fingerprint,
)
from backend.scanners import run_scanners

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def create_zip_bytes(files: dict) -> bytes:
    """Helper to build an in-memory zip archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf.getvalue()


def test_comparison_module_is_importable():
    """Verify that all public symbols of backend.comparison are importable."""
    assert callable(compare_scans)
    assert ScanComparator is not None
    assert ComparisonResult is not None
    assert callable(compute_finding_fingerprint)


def test_fingerprint_stability_across_line_shifts():
    """Verify fingerprints match when code shifts lines but evidence and file remain constant."""
    finding_a = {
        "rule_id": "SECRET_PATTERN_KEY",
        "category": "exposed_secret",
        "location": {"file_path": "src/config.py", "line_start": 10, "line_end": 10},
        "evidence": {"snippet": "API_KEY = [MASKED]"},
    }
    finding_b = {
        "rule_id": "SECRET_PATTERN_KEY",
        "category": "exposed_secret",
        "location": {"file_path": "src/config.py", "line_start": 95, "line_end": 95},
        "evidence": {"snippet": "API_KEY = [MASKED]"},
    }

    fp_a = compute_finding_fingerprint(finding_a)
    fp_b = compute_finding_fingerprint(finding_b)
    assert fp_a == fp_b, "Line number shift altered the finding fingerprint"


def test_fingerprint_distinctness_across_different_files():
    """Verify different file paths produce distinct fingerprints."""
    f1 = {
        "rule_id": "RULE_1",
        "category": "secret",
        "location": {"file_path": "src/a.py"},
        "evidence": "TOKEN",
    }
    f2 = {
        "rule_id": "RULE_1",
        "category": "secret",
        "location": {"file_path": "src/b.py"},
        "evidence": "TOKEN",
    }
    assert compute_finding_fingerprint(f1) != compute_finding_fingerprint(f2)


def test_fingerprint_distinctness_across_different_rules():
    """Verify different rule IDs produce distinct fingerprints."""
    f1 = {
        "rule_id": "RULE_1",
        "category": "secret",
        "location": {"file_path": "src/app.py"},
        "evidence": "TOKEN",
    }
    f2 = {
        "rule_id": "RULE_2",
        "category": "secret",
        "location": {"file_path": "src/app.py"},
        "evidence": "TOKEN",
    }
    assert compute_finding_fingerprint(f1) != compute_finding_fingerprint(f2)


def test_tri_state_comparison_classification():
    """Verify correct classification into resolved, still_present, and new."""
    base_scan = {
        "scan_id": "base-001",
        "coverage": {"completed": ["RULE_RESOLVED", "RULE_PERSISTENT"]},
        "findings": [
            {
                "id": "F-001",
                "rule_id": "RULE_RESOLVED",
                "category": "secret",
                "location": {"file_path": "auth.py", "line_start": 5},
                "evidence": "KEY_1",
            },
            {
                "id": "F-002",
                "rule_id": "RULE_PERSISTENT",
                "category": "secret",
                "location": {"file_path": "db.py", "line_start": 12},
                "evidence": "PASSWORD_1",
            },
        ],
    }

    rescan = {
        "scan_id": "rescan-001",
        "coverage": {"completed": ["RULE_RESOLVED", "RULE_PERSISTENT", "RULE_NEW"]},
        "findings": [
            {
                "id": "F-002-re",
                "rule_id": "RULE_PERSISTENT",
                "category": "secret",
                "location": {"file_path": "db.py", "line_start": 20},  # line shifted
                "evidence": "PASSWORD_1",
            },
            {
                "id": "F-003",
                "rule_id": "RULE_NEW",
                "category": "injection",
                "location": {"file_path": "api.py", "line_start": 50},
                "evidence": "EVAL_CALL",
            },
        ],
    }

    result = compare_scans(base_scan, rescan)

    assert len(result.resolved_by_checks) == 1
    assert result.resolved_by_checks[0]["id"] == "F-001"

    assert len(result.still_present) == 1
    assert result.still_present[0]["id"] == "F-002"

    assert len(result.new) == 1
    assert result.new[0]["id"] == "F-003"

    assert len(result.not_verified) == 0

    assert result.summary["resolved_count"] == 1
    assert result.summary["still_present_count"] == 1
    assert result.summary["new_count"] == 1
    assert result.summary["not_verified_count"] == 0
    assert result.summary["total_baseline"] == 2
    assert result.summary["total_rescan"] == 2


def test_honest_resolution_verification_when_rule_failed():
    """Verify that if a rule failed during rescan, its absence is marked not_verified, not resolved."""
    base_scan = {
        "scan_id": "base-fail-test",
        "coverage": {"completed": ["SECRET_DETECTOR"]},
        "findings": [
            {
                "id": "F-SECRET",
                "rule_id": "SECRET_DETECTOR",
                "category": "secret",
                "location": {"file_path": "app.py"},
                "evidence": "SECRET_VAL",
            }
        ],
    }

    rescan = {
        "scan_id": "rescan-fail-test",
        # The rule failed!
        "coverage": {"completed": [], "failed": ["SECRET_DETECTOR"]},
        "findings": [],  # Empty findings because rule failed!
    }

    result = compare_scans(base_scan, rescan)

    # Must NOT be falsely claimed as resolved!
    assert len(result.resolved_by_checks) == 0, "Failed rule resulted in false resolved status"
    assert len(result.not_verified) == 1
    assert result.not_verified[0]["id"] == "F-SECRET"
    assert "not evaluated or failed" in result.not_verified[0]["verification_note"]
    assert result.summary["not_verified_count"] == 1
    assert result.summary["resolved_count"] == 0


def test_honest_resolution_verification_when_rule_dropped():
    """Verify that if a rule was dropped from rescan coverage, its absence is not_verified."""
    base_scan = {
        "scan_id": "base-dropped",
        "coverage": {"completed": ["RULE_A", "RULE_B"]},
        "findings": [
            {
                "id": "F-B",
                "rule_id": "RULE_B",
                "category": "secret",
                "location": {"file_path": "app.py"},
                "evidence": "EVIDENCE_B",
            }
        ],
    }

    rescan = {
        "scan_id": "rescan-dropped",
        "coverage": {"completed": ["RULE_A"]},  # RULE_B was dropped
        "findings": [],
    }

    result = compare_scans(base_scan, rescan)
    assert len(result.resolved_by_checks) == 0
    assert len(result.not_verified) == 1
    assert result.not_verified[0]["id"] == "F-B"


def test_live_vulnerable_vs_corrected_comparison():
    """Run real scanners on vulnerable and corrected samples and assert deterministic resolution."""
    vulnerable_path = REPO_ROOT / "samples" / "vulnerable"
    corrected_path = REPO_ROOT / "samples" / "corrected"

    assert vulnerable_path.exists()
    assert corrected_path.exists()

    base_scan = run_scanners(str(vulnerable_path))
    rescan = run_scanners(str(corrected_path))

    result = compare_scans(base_scan, rescan)

    assert result.summary["total_baseline"] > 0
    # Corrected sample resolves the planted vulnerabilities!
    assert result.summary["resolved_count"] > 0
    # Corrected sample must have fewer findings than vulnerable baseline
    assert result.summary["total_rescan"] < result.summary["total_baseline"]
    assert len(result.resolved_by_checks) > 0


def test_api_get_scan_workflow():
    """Test POST /api/v1/scans followed by GET /api/v1/scans/{scan_id}."""
    client = TestClient(app)
    zip_bytes = create_zip_bytes(
        {
            "src/index.js": "console.log('hello');\nconst x = 1;",
            "README.md": "# Project",
        }
    )

    create_res = client.post(
        "/api/v1/scans",
        files={"file": ("project.zip", zip_bytes, "application/zip")},
    )
    assert create_res.status_code == 201
    scan_id = create_res.json()["scan_id"]

    get_res = client.get(f"/api/v1/scans/{scan_id}")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["scan_id"] == scan_id
    assert data["status"] in ("completed", "pending")
    assert "coverage" in data


def test_api_get_scan_not_found_returns_404():
    """Verify requesting an unknown scan ID returns HTTP 404."""
    client = TestClient(app)
    res = client.get("/api/v1/scans/non-existent-scan-id-999")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_api_rescan_and_comparison_workflow():
    """Test full rescan workflow: create baseline, rescan with corrected code, verify comparison."""
    client = TestClient(app)

    # 1. Upload vulnerable code as baseline
    vuln_zip = create_zip_bytes(
        {
            "app.py": (
                'API_KEY = "sk-test-abc123xyz456verylongfakekey9876"\n'
                'DB_PASS = "super_secret_password_123"\n'
            )
        }
    )
    base_res = client.post(
        "/api/v1/scans",
        files={"file": ("vuln.zip", vuln_zip, "application/zip")},
    )
    assert base_res.status_code == 201
    base_scan_id = base_res.json()["scan_id"]

    # 2. Rescan with corrected code (secrets removed)
    corrected_zip = create_zip_bytes(
        {
            "app.py": (
                'import os\n'
                'API_KEY = os.environ.get("API_KEY")\n'
                'DB_PASS = os.environ.get("DB_PASS")\n'
            )
        }
    )
    rescan_res = client.post(
        f"/api/v1/scans/{base_scan_id}/rescan",
        files={"file": ("corrected.zip", corrected_zip, "application/zip")},
    )
    assert rescan_res.status_code == 201
    comp_data = rescan_res.json()

    assert comp_data["base_scan_id"] == base_scan_id
    new_scan_id = comp_data["rescan_id"]
    assert new_scan_id != base_scan_id

    # Check comparison classifications
    assert comp_data["summary"]["resolved_count"] > 0
    assert len(comp_data["resolved_by_checks"]) > 0

    # 3. Retrieve comparison via GET /api/v1/scans/{base}/comparison/{new}
    get_comp_res = client.get(f"/api/v1/scans/{base_scan_id}/comparison/{new_scan_id}")
    assert get_comp_res.status_code == 200
    retrieved = get_comp_res.json()
    assert retrieved["base_scan_id"] == base_scan_id
    assert retrieved["rescan_id"] == new_scan_id
    assert retrieved["summary"]["resolved_count"] == comp_data["summary"]["resolved_count"]


def test_api_rescan_non_existent_scan_returns_404():
    """Verify rescan against non-existent scan ID returns HTTP 404."""
    client = TestClient(app)
    zip_bytes = create_zip_bytes({"app.py": "print('ok')"})
    res = client.post(
        "/api/v1/scans/missing-scan-id/rescan",
        files={"file": ("code.zip", zip_bytes, "application/zip")},
    )
    assert res.status_code == 404
    assert "baseline scan 'missing-scan-id' not found" in res.json()["detail"].lower()


def test_api_comparison_with_missing_scan_returns_404():
    """Verify GET comparison returns 404 if either scan does not exist."""
    client = TestClient(app)
    res = client.get("/api/v1/scans/missing-a/comparison/missing-b")
    assert res.status_code == 404
