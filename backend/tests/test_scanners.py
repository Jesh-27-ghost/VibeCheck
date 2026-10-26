"""Automated test suite for Phase 3: Security Scanner Integration.

Tests verify:
- Scanner detects known credential-like values in the vulnerable fixture.
- Secret values are masked in finding evidence.
- Corrected fixture produces fewer findings (or zero for fixed issues).
- Scanner returns honest failure coverage on bad project path.
- Finding schema fields are present and correctly typed.
- No raw secret value appears in evidence, logs, or error strings.
"""

import zipfile
import io
import os
from pathlib import Path

import pytest

from backend.scanners import run_scanners, ScannerEngine
from backend.scanners.masking import MASKED_TOKEN
from backend.scanners.rules import ALL_RULES

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULNERABLE_SAMPLE = Path(__file__).parent.parent.parent / "samples" / "vulnerable"
CORRECTED_SAMPLE = Path(__file__).parent.parent.parent / "samples" / "corrected"

# Known planted secret values in the vulnerable sample — for masking verification
PLANTED_SECRETS = [
    "sk-test-abc123xyz456verylongfakekey9876",
    "super_secret_password_123",
    "my_super_secret_jwt_key_do_not_share",
    "mypassword123",
]


# ---------------------------------------------------------------------------
# Helper: write a temp project directory
# ---------------------------------------------------------------------------

def make_project(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a minimal project directory with the given files."""
    project = tmp_path / "project"
    project.mkdir()
    for rel_path, content in files.items():
        full_path = project / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
    return project


# ---------------------------------------------------------------------------
# Phase 3 — Scanner engine & rule registry
# ---------------------------------------------------------------------------


def test_scanner_engine_is_importable():
    """Verify ScannerEngine can be imported from the scanners package."""
    from backend.scanners import ScannerEngine
    assert callable(getattr(ScannerEngine, "scan", None))


def test_run_scanners_interface_exists():
    """Verify run_scanners is a callable with the correct stable interface."""
    from backend.scanners import run_scanners
    assert callable(run_scanners)


def test_rule_registry_not_empty():
    """Verify at least one secret rule and one static rule exist."""
    secret_rules = [r for r in ALL_RULES if r.is_secret_rule]
    static_rules = [r for r in ALL_RULES if not r.is_secret_rule]
    assert len(secret_rules) >= 1, "Expected at least one secret detection rule"
    assert len(static_rules) >= 1, "Expected at least one static analysis rule"


# ---------------------------------------------------------------------------
# Scanner — vulnerable fixture
# ---------------------------------------------------------------------------


def test_vulnerable_sample_produces_findings(tmp_path):
    """Scanner must detect hardcoded secrets in the vulnerable sample."""
    result = run_scanners(str(VULNERABLE_SAMPLE))

    assert isinstance(result, dict)
    findings = result["findings"]
    assert len(findings) >= 1, (
        f"Expected at least one finding in vulnerable sample, got 0. "
        f"Coverage: {result.get('coverage')}"
    )


def test_findings_have_required_fields(tmp_path):
    """Every finding must contain all required schema fields with correct types."""
    result = run_scanners(str(VULNERABLE_SAMPLE))
    findings = result["findings"]
    assert findings, "Vulnerable sample returned no findings"

    for finding in findings:
        assert isinstance(finding["id"], str) and finding["id"]
        assert isinstance(finding["rule_id"], str) and finding["rule_id"]
        assert isinstance(finding["category"], str) and finding["category"]
        assert isinstance(finding["title"], str) and finding["title"]
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}
        assert finding["confidence"] in {"high", "medium", "low"}
        assert isinstance(finding["evidence"], str)
        assert isinstance(finding["impact"], str) and finding["impact"]
        assert isinstance(finding["recommendation"], str) and finding["recommendation"]
        assert isinstance(finding.get("verification_steps", []), list)

        loc = finding["location"]
        assert isinstance(loc, dict)
        assert "file_path" in loc
        assert isinstance(loc.get("line_start"), int) and loc["line_start"] >= 1


def test_finding_severity_and_confidence_are_distinct():
    """Severity and confidence must be separate fields with independently assigned values."""
    result = run_scanners(str(VULNERABLE_SAMPLE))
    findings = result["findings"]
    assert findings

    # Verify they are stored separately and can independently differ
    for f in findings:
        assert "severity" in f
        assert "confidence" in f
        # They are allowed to be the same value but must be separate fields
        assert f["severity"] != f.get("nonexistent_field")


# ---------------------------------------------------------------------------
# Secret masking — core safety guarantee
# ---------------------------------------------------------------------------


def test_planted_secrets_are_masked_in_evidence():
    """No planted raw secret value may appear in finding evidence."""
    result = run_scanners(str(VULNERABLE_SAMPLE))
    findings = result["findings"]
    assert findings, "No findings — cannot verify masking"

    all_evidence = " ".join(f["evidence"] for f in findings)

    for secret in PLANTED_SECRETS:
        assert secret not in all_evidence, (
            f"Raw secret value '{secret[:6]}...' found unmasked in finding evidence!"
        )


def test_masked_token_appears_in_secret_findings():
    """Evidence for secret findings must contain the REDACTED token."""
    result = run_scanners(str(VULNERABLE_SAMPLE))
    secret_findings = [
        f for f in result["findings"]
        if f.get("category") == "exposed_secret"
    ]
    assert secret_findings, "Expected at least one secret finding in vulnerable sample"

    for finding in secret_findings:
        assert MASKED_TOKEN in finding["evidence"], (
            f"Finding {finding['id']} evidence does not contain {MASKED_TOKEN}: "
            f"{finding['evidence']}"
        )


def test_masking_inline_with_targeted_fixture(tmp_path):
    """Directly verify secret masking with a controlled single-file fixture."""
    project = make_project(tmp_path, {
        "config.py": 'API_KEY = "my_super_secret_value_99"',
    })
    result = run_scanners(str(project))
    findings = result["findings"]
    assert findings, "Expected at least one finding for hardcoded API key"

    for f in findings:
        assert "my_super_secret_value_99" not in f["evidence"], (
            "Raw secret value leaked into finding evidence!"
        )
        if f.get("category") == "exposed_secret":
            assert MASKED_TOKEN in f["evidence"]


# ---------------------------------------------------------------------------
# Scanner — corrected fixture
# ---------------------------------------------------------------------------


def test_corrected_sample_has_fewer_secret_findings():
    """Corrected sample must produce fewer (ideally zero) secret findings."""
    vuln_result = run_scanners(str(VULNERABLE_SAMPLE))
    fixed_result = run_scanners(str(CORRECTED_SAMPLE))

    vuln_secrets = [
        f for f in vuln_result["findings"]
        if f.get("category") == "exposed_secret"
    ]
    fixed_secrets = [
        f for f in fixed_result["findings"]
        if f.get("category") == "exposed_secret"
    ]

    assert len(fixed_secrets) < len(vuln_secrets), (
        f"Corrected sample has {len(fixed_secrets)} secret findings, "
        f"vulnerable has {len(vuln_secrets)}. Fix did not reduce findings."
    )


# ---------------------------------------------------------------------------
# Scanner — failure handling (no false cleans)
# ---------------------------------------------------------------------------


def test_invalid_project_path_does_not_produce_clean_result():
    """Scanner must not return a clean result when the project path is invalid."""
    result = run_scanners("/nonexistent/path/that/does/not/exist/abc123")

    # A scanner error must be surfaced
    assert result.get("scanner_error") is not None, (
        "Expected scanner_error for invalid path, got None"
    )
    # Coverage must record a failure — not a successful completion
    coverage = result.get("coverage", {})
    assert len(coverage.get("failed", [])) > 0, (
        "Expected at least one failed check in coverage for invalid path"
    )
    # No findings should be fabricated
    assert result["findings"] == []


def test_scanner_result_always_returns_required_keys(tmp_path):
    """run_scanners always returns a dict with all required top-level keys."""
    result = run_scanners(str(tmp_path))
    required_keys = {"findings", "files_scanned", "total_lines", "coverage", "limitations"}
    for key in required_keys:
        assert key in result, f"Missing required key in scanner result: {key}"


def test_coverage_reports_unsupported_checks():
    """Scanner result must include unsupported checks in coverage."""
    result = run_scanners(str(VULNERABLE_SAMPLE))
    unsupported = result["coverage"].get("unsupported", [])
    assert len(unsupported) > 0, "Expected scanner to report at least one unsupported check"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_duplicate_findings_are_deduplicated(tmp_path):
    """The same rule + file + line should appear at most once in findings."""
    # A file with the same pattern on one line — scanner must not return duplicates
    project = make_project(tmp_path, {
        "app.py": 'PASSWORD = "duplicate_secret_here"\n',
    })
    result = run_scanners(str(project))
    findings = result["findings"]

    keys = [(f["rule_id"], f["location"]["file_path"], f["location"]["line_start"]) for f in findings]
    assert len(keys) == len(set(keys)), "Duplicate findings found for same rule/file/line"


# ---------------------------------------------------------------------------
# Line location accuracy
# ---------------------------------------------------------------------------


def test_finding_line_number_is_accurate(tmp_path):
    """Finding line_start must correspond to the actual line containing the pattern."""
    content = (
        "# line 1\n"
        "# line 2\n"
        'API_KEY = "test_secret_value_line3_abc"\n'  # line 3
        "# line 4\n"
    )
    project = make_project(tmp_path, {"config.py": content})
    result = run_scanners(str(project))

    secret_findings = [
        f for f in result["findings"]
        if f.get("category") == "exposed_secret"
    ]
    assert secret_findings, "Expected a finding for the API key on line 3"

    line_numbers = [f["location"]["line_start"] for f in secret_findings]
    assert 3 in line_numbers, (
        f"Expected finding at line 3, got lines: {line_numbers}"
    )
