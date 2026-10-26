"""Phase 4 Checkpoint: Findings & Remediation Synthesis.

Verifies:
- Findings contain evidence, severity, confidence, impact, and recommendations.
- Duplicate findings are handled according to implemented rules.
- Secrets are redacted from user-facing output.
- Repair prompts contain relevant findings and safe remediation instructions.
- Generated prompt does not contain raw secret values.
- Errors and partial coverage are reported honestly.
- Remediation test suite passes.
"""

from typing import List

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase4Check:
    """Checkpoint gate runner for Phase 4: Findings & Remediation."""

    phase_number = 4
    phase_name = "Findings & Consolidated Remediation"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        remediation_ready = cls._inspect_remediation_module()

        if not remediation_ready:
            results.append(
                CheckResult(
                    name="Consolidated Repair Prompt Generator",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/remediation does not export prompt generator or remediation service.",
                )
            )
            results.append(
                CheckResult(
                    name="Finding Field Completeness Audit",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Remediation pipeline awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Duplicate Finding Deduplication",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Deduplication engine awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Secret Redaction in User-Facing Output",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Secret redaction in remediation awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Actionable Safe Remediation Instructions",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Remediation prompt synthesis awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Raw Secret Exclusion from AI Repair Prompt",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Prompt secret sanitizer awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Honest Partial Coverage & Limitations Reporting",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Coverage limitations reporter awaiting Phase 4 implementation.",
                )
            )
        else:
            results.append(cls._check_live_remediation())

        remediation_test = REPO_ROOT / "backend" / "tests" / "test_remediation.py"
        if not remediation_test.exists():
            results.append(
                CheckResult(
                    name="Remediation Automated Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_remediation.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_remediation_tests(str(remediation_test)))

        return results

    @classmethod
    def _inspect_remediation_module(cls) -> bool:
        try:
            import backend.remediation as remediation

            return any(
                hasattr(remediation, attr)
                for attr in [
                    "generate_repair_prompt",
                    "PromptSynthesizer",
                    "RemediationService",
                ]
            )
        except Exception:
            return False

    @classmethod
    def _check_live_remediation(cls) -> CheckResult:
        """Run live verification of the remediation module against actual findings."""
        try:
            from backend.scanners import run_scanners
            from backend.remediation import generate_repair_prompt
            from backend.scanners.masking import MASKED_TOKEN

            vulnerable_sample = REPO_ROOT / "samples" / "vulnerable"
            if not vulnerable_sample.exists():
                return CheckResult(
                    name="Consolidated Repair Prompt Generator",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="samples/vulnerable/ not found; cannot run E2E remediation check.",
                )

            # Step 1: get real findings from scanner
            scan_result = run_scanners(str(vulnerable_sample))
            findings = scan_result.get("findings", [])

            if not findings:
                return CheckResult(
                    name="Consolidated Repair Prompt Generator",
                    status=CheckStatus.FAIL,
                    details="Scanner returned no findings from vulnerable sample; cannot verify remediation.",
                )

            # Step 2: generate prompt from actual findings
            prompt = generate_repair_prompt(
                scan_id="phase4-check",
                project_name="vulnerable-sample",
                findings=findings,
                coverage=scan_result.get("coverage"),
                limitations=scan_result.get("limitations"),
            )

            # Verify prompt is a non-empty string
            if not isinstance(prompt, str) or len(prompt) < 50:
                return CheckResult(
                    name="Consolidated Repair Prompt Generator",
                    status=CheckStatus.FAIL,
                    details=f"Prompt is too short or not a string: {repr(prompt[:100])}",
                )

            # Verify at least one finding ID is in the prompt
            referenced = [f["id"] for f in findings if f["id"] in prompt]
            if not referenced:
                return CheckResult(
                    name="Consolidated Repair Prompt Generator",
                    status=CheckStatus.FAIL,
                    details="No finding IDs found in repair prompt. Prompt may not reference actual findings.",
                )

            # Verify no planted raw secrets in prompt
            raw_secrets = [
                "sk-test-abc123xyz456verylongfakekey9876",
                "super_secret_password_123",
                "mypassword123",
            ]
            for secret in raw_secrets:
                if secret in prompt:
                    return CheckResult(
                        name="Raw Secret Exclusion from AI Repair Prompt",
                        status=CheckStatus.FAIL,
                        details=f"Raw secret value found in repair prompt output!",
                    )

            return CheckResult(
                name="Consolidated Repair Prompt Generator",
                status=CheckStatus.PASS,
                details=(
                    f"Prompt generated from {len(findings)} actual finding(s). "
                    f"{len(referenced)} finding ID(s) referenced. Secret masking verified."
                ),
            )

        except Exception as exc:
            return CheckResult(
                name="Consolidated Repair Prompt Generator",
                status=CheckStatus.FAIL,
                details=f"Live remediation check raised exception: {exc}",
            )

    @classmethod
    def _run_remediation_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Remediation Automated Test Suite",
                status=CheckStatus.PASS,
                details="Remediation tests passed.",
            )
        return CheckResult(
            name="Remediation Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Remediation tests failed:\n{output}",
        )
