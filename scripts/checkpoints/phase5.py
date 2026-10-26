"""Phase 5 Checkpoint: Rescan Comparison & State Tracking.

Verifies:
- Baseline scan persistence and retrieval.
- Rescan execution against corrected fixture.
- Stable finding comparison using rule_id, location, and evidence.
- State transitions: resolved, unresolved (persistent), and new findings.
- Honest resolution check (unverifiable findings not falsely marked resolved).
- Comparison test suite passes.
"""

from pathlib import Path
from typing import List

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase5Check:
    """Checkpoint gate runner for Phase 5: Rescan Comparison."""

    phase_number = 5
    phase_name = "Rescan Comparison & Verification"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        comparison_ready = cls._inspect_comparison_module()

        if not comparison_ready:
            results.append(
                CheckResult(
                    name="Comparison Engine Interface Implementation",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/comparison does not export scan comparison service or diff engine.",
                )
            )
            results.append(
                CheckResult(
                    name="Baseline Scan Storage & Retrieval",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Baseline persistence awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Corrected Fixture Rescan Ingestion",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Rescan ingestion awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Stable Finding Matching (Rule, Location, Evidence)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Diff matching logic awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Tri-State Finding Classification (Resolved / Persistent / New)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="State classification awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Honest Resolution Verification (No False Clears)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Verification guard awaiting Phase 5 implementation.",
                )
            )
        else:
            results.extend(cls._run_live_comparison_checks())

        comparison_test = REPO_ROOT / "backend" / "tests" / "test_comparison.py"
        if not comparison_test.exists():
            results.append(
                CheckResult(
                    name="Comparison Automated Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_comparison.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_comparison_tests(str(comparison_test)))

        return results

    @classmethod
    def _inspect_comparison_module(cls) -> bool:
        try:
            import backend.comparison as comparison

            return any(
                hasattr(comparison, attr)
                for attr in [
                    "compare_scans",
                    "ScanComparator",
                    "ComparisonResult",
                ]
            )
        except Exception:
            return False

    @classmethod
    def _run_live_comparison_checks(cls) -> List[CheckResult]:
        """Run all live deterministic checks for Phase 5."""
        checks: List[CheckResult] = []

        # 1. Interface check
        try:
            from backend.comparison import (
                ComparisonResult,
                ScanComparator,
                compare_scans,
                compute_finding_fingerprint,
            )

            checks.append(
                CheckResult(
                    name="Comparison Engine Interface Implementation",
                    status=CheckStatus.PASS,
                    details="backend.comparison exports compare_scans, ScanComparator, and ComparisonResult.",
                )
            )
        except Exception as exc:
            checks.append(
                CheckResult(
                    name="Comparison Engine Interface Implementation",
                    status=CheckStatus.FAIL,
                    details=f"Failed to import comparison symbols: {exc}",
                )
            )
            return checks

        # 2. Baseline storage & retrieval check
        try:
            from backend.app.api.router import SCAN_STORE, api_router

            routes = [route.path for route in api_router.routes]
            has_get = "/scans/{scan_id}" in routes
            has_rescan = "/scans/{scan_id}/rescan" in routes
            has_comp = "/scans/{scan_id}/comparison/{new_scan_id}" in routes

            if has_get and has_rescan and has_comp:
                checks.append(
                    CheckResult(
                        name="Baseline Scan Storage & Retrieval",
                        status=CheckStatus.PASS,
                        details="Scan store active; GET, rescan, and comparison endpoints registered.",
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        name="Baseline Scan Storage & Retrieval",
                        status=CheckStatus.FAIL,
                        details=f"Missing endpoints. Registered: {routes}",
                    )
                )
        except Exception as exc:
            checks.append(
                CheckResult(
                    name="Baseline Scan Storage & Retrieval",
                    status=CheckStatus.FAIL,
                    details=f"Scan store verification failed: {exc}",
                )
            )

        # 3. Corrected fixture rescan ingestion check
        try:
            from backend.scanners import run_scanners

            corrected_path = REPO_ROOT / "samples" / "corrected"
            vulnerable_path = REPO_ROOT / "samples" / "vulnerable"

            if not corrected_path.exists() or not vulnerable_path.exists():
                checks.append(
                    CheckResult(
                        name="Corrected Fixture Rescan Ingestion",
                        status=CheckStatus.FAIL,
                        details="Sample fixtures missing in samples/.",
                    )
                )
            else:
                base_scan = run_scanners(str(vulnerable_path))
                rescan = run_scanners(str(corrected_path))
                comp = compare_scans(base_scan, rescan)

                if comp.summary["resolved_count"] > 0:
                    checks.append(
                        CheckResult(
                            name="Corrected Fixture Rescan Ingestion",
                            status=CheckStatus.PASS,
                            details=(
                                f"Scanned corrected fixture: {comp.summary['resolved_count']} finding(s) "
                                f"resolved from baseline of {comp.summary['total_baseline']}."
                            ),
                        )
                    )
                else:
                    checks.append(
                        CheckResult(
                            name="Corrected Fixture Rescan Ingestion",
                            status=CheckStatus.FAIL,
                            details="Rescan against corrected sample detected 0 resolved findings.",
                        )
                    )
        except Exception as exc:
            checks.append(
                CheckResult(
                    name="Corrected Fixture Rescan Ingestion",
                    status=CheckStatus.FAIL,
                    details=f"Fixture rescan check failed: {exc}",
                )
            )

        # 4. Stable finding matching check
        try:
            f1 = {
                "rule_id": "SEC_1",
                "category": "secret",
                "location": {"file_path": "a.py", "line_start": 5},
                "evidence": "TOKEN_VAL",
            }
            f2 = {
                "rule_id": "SEC_1",
                "category": "secret",
                "location": {"file_path": "a.py", "line_start": 80},  # line shifted
                "evidence": "TOKEN_VAL",
            }
            f3 = {
                "rule_id": "SEC_1",
                "category": "secret",
                "location": {"file_path": "b.py", "line_start": 5},  # different file
                "evidence": "TOKEN_VAL",
            }
            fp1 = compute_finding_fingerprint(f1)
            fp2 = compute_finding_fingerprint(f2)
            fp3 = compute_finding_fingerprint(f3)

            if fp1 == fp2 and fp1 != fp3:
                checks.append(
                    CheckResult(
                        name="Stable Finding Matching (Rule, Location, Evidence)",
                        status=CheckStatus.PASS,
                        details="Fingerprints remain stable across line shifts and distinct across files.",
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        name="Stable Finding Matching (Rule, Location, Evidence)",
                        status=CheckStatus.FAIL,
                        details=f"Fingerprint invariant violated: fp1==fp2: {fp1==fp2}, fp1!=fp3: {fp1!=fp3}",
                    )
                )
        except Exception as exc:
            checks.append(
                CheckResult(
                    name="Stable Finding Matching (Rule, Location, Evidence)",
                    status=CheckStatus.FAIL,
                    details=f"Fingerprint check failed: {exc}",
                )
            )

        # 5. Tri-state classification check
        try:
            base_data = {
                "scan_id": "b1",
                "coverage": {"completed": ["R1", "R2"]},
                "findings": [
                    {"id": "1", "rule_id": "R1", "category": "cat", "location": {"file_path": "x.py"}, "evidence": "E1"},
                    {"id": "2", "rule_id": "R2", "category": "cat", "location": {"file_path": "y.py"}, "evidence": "E2"},
                ],
            }
            rescan_data = {
                "scan_id": "r1",
                "coverage": {"completed": ["R1", "R2", "R3"]},
                "findings": [
                    {"id": "2-shift", "rule_id": "R2", "category": "cat", "location": {"file_path": "y.py"}, "evidence": "E2"},
                    {"id": "3", "rule_id": "R3", "category": "cat", "location": {"file_path": "z.py"}, "evidence": "E3"},
                ],
            }
            comp = compare_scans(base_data, rescan_data)
            has_resolved = len(comp.resolved_by_checks) == 1 and comp.resolved_by_checks[0]["id"] == "1"
            has_persistent = len(comp.still_present) == 1 and comp.still_present[0]["id"] == "2"
            has_new = len(comp.new) == 1 and comp.new[0]["id"] == "3"

            if has_resolved and has_persistent and has_new:
                checks.append(
                    CheckResult(
                        name="Tri-State Finding Classification (Resolved / Persistent / New)",
                        status=CheckStatus.PASS,
                        details="Findings accurately partitioned into resolved_by_checks, still_present, and new.",
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        name="Tri-State Finding Classification (Resolved / Persistent / New)",
                        status=CheckStatus.FAIL,
                        details=(
                            f"Classification failed: resolved={len(comp.resolved_by_checks)}, "
                            f"still_present={len(comp.still_present)}, new={len(comp.new)}"
                        ),
                    )
                )
        except Exception as exc:
            checks.append(
                CheckResult(
                    name="Tri-State Finding Classification (Resolved / Persistent / New)",
                    status=CheckStatus.FAIL,
                    details=f"Tri-state check failed: {exc}",
                )
            )

        # 6. Honest resolution check
        try:
            base_data = {
                "scan_id": "b-honest",
                "coverage": {"completed": ["R_FAIL"]},
                "findings": [
                    {"id": "F1", "rule_id": "R_FAIL", "category": "cat", "location": {"file_path": "x.py"}, "evidence": "E1"}
                ],
            }
            rescan_data = {
                "scan_id": "r-honest",
                "coverage": {"completed": [], "failed": ["R_FAIL"]},
                "findings": [],
            }
            comp = compare_scans(base_data, rescan_data)
            no_false_resolve = len(comp.resolved_by_checks) == 0
            placed_in_not_verified = len(comp.not_verified) == 1

            if no_false_resolve and placed_in_not_verified:
                checks.append(
                    CheckResult(
                        name="Honest Resolution Verification (No False Clears)",
                        status=CheckStatus.PASS,
                        details="Findings whose rules failed or were skipped are guarded into not_verified.",
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        name="Honest Resolution Verification (No False Clears)",
                        status=CheckStatus.FAIL,
                        details="Failed rule was falsely marked resolved or not captured in not_verified.",
                    )
                )
        except Exception as exc:
            checks.append(
                CheckResult(
                    name="Honest Resolution Verification (No False Clears)",
                    status=CheckStatus.FAIL,
                    details=f"Honest resolution check failed: {exc}",
                )
            )

        return checks

    @classmethod
    def _run_comparison_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Comparison Automated Test Suite",
                status=CheckStatus.PASS,
                details="Comparison tests passed.",
            )
        return CheckResult(
            name="Comparison Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Comparison tests failed:\n{output}",
        )
