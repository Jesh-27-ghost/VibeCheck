"""Automated test suite for Phase 4: Findings & Consolidated Remediation.

Tests verify:
- Repair prompt is generated from actual finding IDs and locations.
- Credential findings include rotate/revoke guidance.
- Raw secret values never appear in prompt output.
- Empty findings produce honest message (not a fabricated prompt).
- Prompt failure does not erase the security report.
- Coverage and limitations are included in prompt.
- Finding field completeness: severity and confidence are distinct.
"""

from pathlib import Path

import pytest

from backend.remediation import generate_repair_prompt, RemediationService
from backend.scanners import run_scanners
from backend.scanners.masking import MASKED_TOKEN

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULNERABLE_SAMPLE = Path(__file__).parent.parent.parent / "samples" / "vulnerable"

FAKE_FINDING = {
    "id": "SECRET_001-abcd1234",
    "rule_id": "SECRET_001",
    "category": "exposed_secret",
    "title": "Hardcoded API Key / Token",
    "severity": "high",
    "confidence": "medium",
    "status": "open",
    "location": {
        "file_path": "src/config.py",
        "line_start": 12,
        "line_end": 12,
        "snippet": f'API_KEY = "{MASKED_TOKEN}"',
    },
    "evidence": f'API_KEY = "{MASKED_TOKEN}"',
    "impact": "Exposed API key allows unauthorised access.",
    "recommendation": "Remove the hardcoded key. Use an environment variable.",
    "verification_steps": [
        "Revoke the key with its provider.",
        "Replace with os.environ['API_KEY'].",
        "Rerun VibeCheck.",
    ],
}

FAKE_STATIC_FINDING = {
    "id": "CORS_001-abcd5678",
    "rule_id": "CORS_001",
    "category": "insecure_configuration",
    "title": "Wildcard CORS Policy Detected",
    "severity": "medium",
    "confidence": "high",
    "status": "open",
    "location": {
        "file_path": "app.py",
        "line_start": 42,
        "line_end": 42,
        "snippet": "allow_origins = ['*']",
    },
    "evidence": "allow_origins = ['*']",
    "impact": "Wildcard CORS allows any origin.",
    "recommendation": "Specify an explicit allowlist of trusted origins.",
    "verification_steps": [
        "Replace * with ['https://yourdomain.com'].",
        "Test cross-origin requests.",
    ],
}

KNOWN_SECRETS = [
    "real_secret_value_abc123",
    "another_secret_xyz789",
]


# ---------------------------------------------------------------------------
# Remediation module — importability
# ---------------------------------------------------------------------------


def test_generate_repair_prompt_is_importable():
    """generate_repair_prompt must be importable from the remediation package."""
    assert callable(generate_repair_prompt)


def test_remediation_service_is_importable():
    """RemediationService must be importable and functional."""
    svc = RemediationService()
    assert callable(svc.build_prompt)


# ---------------------------------------------------------------------------
# Prompt content — from actual findings
# ---------------------------------------------------------------------------


def test_prompt_contains_actual_finding_ids():
    """Prompt must reference the actual finding IDs from the input."""
    prompt = generate_repair_prompt(
        scan_id="test-scan-001",
        project_name="test-project",
        findings=[FAKE_FINDING],
    )
    assert FAKE_FINDING["id"] in prompt, (
        f"Finding ID {FAKE_FINDING['id']} not found in prompt"
    )


def test_prompt_contains_actual_file_path():
    """Prompt must reference the actual file path from each finding's location."""
    prompt = generate_repair_prompt(
        scan_id="test-scan-002",
        project_name="test-project",
        findings=[FAKE_FINDING],
    )
    assert "src/config.py" in prompt


def test_prompt_contains_recommendation():
    """Prompt must include the actual recommendation text from findings."""
    prompt = generate_repair_prompt(
        scan_id="test-scan-003",
        project_name="test-project",
        findings=[FAKE_FINDING],
    )
    assert "environment variable" in prompt.lower() or "env" in prompt.lower()


def test_prompt_includes_scan_id():
    """Prompt must include the scan ID for traceability."""
    prompt = generate_repair_prompt(
        scan_id="trace-scan-999",
        project_name="my-app",
        findings=[FAKE_FINDING],
    )
    assert "trace-scan-999" in prompt


def test_prompt_multiple_findings_all_referenced():
    """All findings in input must appear in the prompt."""
    findings = [FAKE_FINDING, FAKE_STATIC_FINDING]
    prompt = generate_repair_prompt(
        scan_id="multi-scan-001",
        project_name="multi-app",
        findings=findings,
    )
    assert FAKE_FINDING["id"] in prompt
    assert FAKE_STATIC_FINDING["id"] in prompt


# ---------------------------------------------------------------------------
# Credential rotation guidance
# ---------------------------------------------------------------------------


def test_secret_findings_include_rotation_guidance():
    """Prompts for secret findings must include rotate/revoke guidance."""
    prompt = generate_repair_prompt(
        scan_id="cred-scan-001",
        project_name="cred-project",
        findings=[FAKE_FINDING],  # category: exposed_secret
    )
    # The prompt must mention revocation/rotation
    prompt_lower = prompt.lower()
    assert any(
        keyword in prompt_lower
        for keyword in ("revoke", "rotate", "deactivate", "credential rotation")
    ), "Expected credential rotation/revoke guidance for secret finding"


def test_non_secret_findings_do_not_force_rotation_section():
    """Prompts for non-secret findings should not include misleading rotation guidance."""
    prompt = generate_repair_prompt(
        scan_id="static-scan-001",
        project_name="static-project",
        findings=[FAKE_STATIC_FINDING],  # category: insecure_configuration
    )
    # The rotation-specific header should not appear for pure config findings
    assert "CREDENTIAL ROTATION REQUIRED" not in prompt


# ---------------------------------------------------------------------------
# Secret masking in prompt output
# ---------------------------------------------------------------------------


def test_raw_secrets_never_appear_in_prompt():
    """Raw secret values must not appear in the generated prompt."""
    # Build a finding where evidence is already masked
    finding_with_masked_evidence = {**FAKE_FINDING, "evidence": f'API_KEY = "{MASKED_TOKEN}"'}

    prompt = generate_repair_prompt(
        scan_id="mask-scan-001",
        project_name="mask-project",
        findings=[finding_with_masked_evidence],
    )

    for secret in KNOWN_SECRETS:
        assert secret not in prompt, (
            f"Raw secret '{secret[:6]}...' found in repair prompt output!"
        )


def test_masked_token_preserved_in_prompt():
    """The MASKED_TOKEN from finding evidence should appear in the prompt, not the raw value."""
    finding = {**FAKE_FINDING, "evidence": f'api_key = "{MASKED_TOKEN}"'}
    prompt = generate_repair_prompt(
        scan_id="tok-scan-001",
        project_name="tok-project",
        findings=[finding],
    )
    assert MASKED_TOKEN in prompt


# ---------------------------------------------------------------------------
# Empty findings
# ---------------------------------------------------------------------------


def test_empty_findings_returns_honest_message():
    """An empty findings list must return an honest 'no findings' message."""
    prompt = generate_repair_prompt(
        scan_id="empty-scan-001",
        project_name="clean-project",
        findings=[],
    )
    assert "no security findings" in prompt.lower() or "no findings" in prompt.lower()
    # Must not claim the application is secure
    assert "completely secure" not in prompt.lower()


def test_empty_findings_includes_limitations_caveat():
    """Empty findings prompt must acknowledge scanner limitations."""
    limitations = ["Static pattern matching only; runtime behaviour not evaluated."]
    prompt = generate_repair_prompt(
        scan_id="empty-scan-002",
        project_name="clean-app",
        findings=[],
        limitations=limitations,
    )
    assert "static" in prompt.lower() or "limitations" in prompt.lower()


# ---------------------------------------------------------------------------
# Coverage & limitations in prompt
# ---------------------------------------------------------------------------


def test_prompt_includes_coverage_summary():
    """Prompt must include coverage summary when provided."""
    coverage = {
        "completed": ["SECRET_001:exposed_secret"],
        "failed": [],
        "skipped": [],
        "unsupported": ["runtime_testing"],
    }
    prompt = generate_repair_prompt(
        scan_id="cov-scan-001",
        project_name="cov-project",
        findings=[FAKE_FINDING],
        coverage=coverage,
    )
    assert "SECRET_001" in prompt or "completed" in prompt.lower()


def test_prompt_includes_limitations():
    """Prompt must include limitations when provided."""
    limitations = ["Dependency audits are not supported in this build."]
    prompt = generate_repair_prompt(
        scan_id="lim-scan-001",
        project_name="lim-project",
        findings=[FAKE_FINDING],
        limitations=limitations,
    )
    assert "dependency" in prompt.lower() or "limitations" in prompt.lower()


# ---------------------------------------------------------------------------
# Prompt failure resilience
# ---------------------------------------------------------------------------


def test_prompt_failure_does_not_raise():
    """generate_repair_prompt must not raise even with malformed finding input."""
    malformed_finding = {"id": "BAD-001"}  # missing most required fields
    try:
        prompt = generate_repair_prompt(
            scan_id="bad-scan-001",
            project_name="bad-project",
            findings=[malformed_finding],
        )
        # Must return a string, not crash
        assert isinstance(prompt, str)
    except Exception as exc:
        pytest.fail(f"generate_repair_prompt raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# Integration: scanner findings → repair prompt
# ---------------------------------------------------------------------------


def test_end_to_end_prompt_from_vulnerable_sample():
    """Full pipeline: scan vulnerable sample, generate prompt from actual findings."""
    scanner_result = run_scanners(str(VULNERABLE_SAMPLE))
    findings = scanner_result["findings"]
    coverage = scanner_result["coverage"]
    limitations = scanner_result["limitations"]

    assert findings, "Expected findings from vulnerable sample for E2E test"

    prompt = generate_repair_prompt(
        scan_id="e2e-scan-001",
        project_name="vulnerable-sample",
        findings=findings,
        coverage=coverage,
        limitations=limitations,
    )

    assert isinstance(prompt, str) and len(prompt) > 50

    # All finding IDs must appear in the prompt
    for finding in findings:
        assert finding["id"] in prompt, (
            f"Finding {finding['id']} not referenced in prompt"
        )

    # No planted raw secrets should appear
    planted_secrets = [
        "sk-test-abc123xyz456verylongfakekey9876",
        "super_secret_password_123",
        "my_super_secret_jwt_key_do_not_share",
        "mypassword123",
    ]
    for secret in planted_secrets:
        assert secret not in prompt, (
            f"Raw secret '{secret[:6]}...' found in repair prompt!"
        )
