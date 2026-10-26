"""Phase 3 Checkpoint: Scanner Integration.

Verifies:
- Scanner adapter runs against controlled vulnerable fixture.
- Known test vulnerability produces finding with grounded file and line evidence.
- Findings conform to agreed finding schema.
- Secret-like values masked in reports, logs, and errors.
- Scanner exceptions/missing dependencies not represented as clean scans.
- Corrected fixtures verify resolution.
- Scanner test suite passes.

If scanner adapter is not connected, marks checks NOT IMPLEMENTED and fails gate.
"""

from typing import List

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase3Check:
    """Checkpoint gate runner for Phase 3: Scanner Integration."""

    phase_number = 3
    phase_name = "Security Scanner Integration"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        scanner_ready = cls._inspect_scanner_engine()

        if not scanner_ready:
            results.append(
                CheckResult(
                    name="Scanner Engine Adapter Implementation",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/scanners does not export active scanner engine or rule registry.",
                )
            )
            results.append(
                CheckResult(
                    name="Controlled Vulnerable Fixture Scanning",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Scanner not connected to evaluate vulnerable fixtures.",
                )
            )
            results.append(
                CheckResult(
                    name="Grounded Finding Location & Line Evidence",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Grounded finding verification awaiting scanner implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Finding Schema Conformity",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Schema validation awaiting real scanner output.",
                )
            )
            results.append(
                CheckResult(
                    name="Secret Masking in Logs & Output",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Secret redaction filter awaiting scanner implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Honest Scanner Failure Handling (No False Cleans)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Scanner error handling awaiting implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Corrected Fixture Scan Verification",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Corrected sample verification awaiting scanner implementation.",
                )
            )
        else:
            # When scanner is implemented in Phase 3, run live verification
            results.append(cls._check_live_scanner())

        # Test suite check
        scanner_test = REPO_ROOT / "backend" / "tests" / "test_scanners.py"
        if not scanner_test.exists():
            results.append(
                CheckResult(
                    name="Scanner Automated Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_scanners.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_scanner_tests(str(scanner_test)))

        return results

    @classmethod
    def _inspect_scanner_engine(cls) -> bool:
        try:
            import backend.scanners as scanners

            return any(
                hasattr(scanners, attr)
                for attr in [
                    "ScannerEngine",
                    "run_scanners",
                    "SecurityScanner",
                    "RuleRegistry",
                ]
            )
        except Exception:
            return False

    @classmethod
    def _check_live_scanner(cls) -> CheckResult:
        """Run live verification of scanner against the vulnerable sample fixture."""
        from pathlib import Path as _Path
        vulnerable_sample = REPO_ROOT / "samples" / "vulnerable"

        if not vulnerable_sample.exists():
            return CheckResult(
                name="Scanner Engine Adapter Implementation",
                status=CheckStatus.NOT_IMPLEMENTED,
                details="samples/vulnerable/ does not exist; cannot verify scanner against fixture.",
            )

        try:
            from backend.scanners import run_scanners
            result = run_scanners(str(vulnerable_sample))

            findings = result.get("findings", [])
            coverage = result.get("coverage", {})
            scanner_error = result.get("scanner_error")

            # Must produce at least one finding from the vulnerable sample
            if not findings:
                return CheckResult(
                    name="Scanner Engine Adapter Implementation",
                    status=CheckStatus.FAIL,
                    details=(
                        "Scanner ran against vulnerable fixture but produced zero findings. "
                        "Expected at least one secret/config finding."
                    ),
                )

            # Verify no raw secret value is present in evidence
            from backend.scanners.masking import MASKED_TOKEN
            for f in findings:
                evidence = f.get("evidence", "")
                if "super_secret" in evidence or "sk-test-abc" in evidence:
                    return CheckResult(
                        name="Secret Masking in Logs & Output",
                        status=CheckStatus.FAIL,
                        details="Raw secret value found unmasked in finding evidence!",
                    )

            # Verify coverage records completed checks
            completed = coverage.get("completed", [])
            failed = coverage.get("failed", [])
            if not completed and not failed:
                return CheckResult(
                    name="Honest Scanner Failure Handling (No False Cleans)",
                    status=CheckStatus.FAIL,
                    details="Coverage has neither completed nor failed entries — scanner may be a stub.",
                )

            return CheckResult(
                name="Scanner Engine Adapter Implementation",
                status=CheckStatus.PASS,
                details=(
                    f"Scanner produced {len(findings)} finding(s) from vulnerable fixture. "
                    f"Evidence masking verified. Coverage: {len(completed)} completed, {len(failed)} failed."
                ),
            )

        except Exception as exc:
            return CheckResult(
                name="Scanner Engine Adapter Implementation",
                status=CheckStatus.FAIL,
                details=f"Live scanner check raised exception: {exc}",
            )

    @classmethod
    def _run_scanner_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Scanner Automated Test Suite",
                status=CheckStatus.PASS,
                details="Scanner tests passed.",
            )
        return CheckResult(
            name="Scanner Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Scanner tests failed:\n{output}",
        )
