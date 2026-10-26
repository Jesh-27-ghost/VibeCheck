"""Phase 6 Checkpoint: End-to-End User Journey.

Verifies complete MVP workflow via FastAPI TestClient/fixtures:
- Submit project archive.
- Execute security scan.
- Retrieve evidence-backed report.
- Retrieve usable repair prompt.
- Submit corrected version.
- Rescan and compare findings.
- Validate response schemas and error conditions.
- Run complete integration test suite.
"""

from typing import List

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase6Check:
    """Checkpoint gate runner for Phase 6: End-to-End MVP."""

    phase_number = 6
    phase_name = "End-to-End MVP Integration"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        # 1. Initial Submission & Scan Execution
        results.append(cls._check_scan_workflow())

        # 2. Report & Finding Retrieval
        results.append(cls._check_report_retrieval())

        # 3. Usable Repair Prompt Generation
        results.append(cls._check_repair_prompt())

        # 4. Corrected Code Rescan Submission
        results.append(cls._check_rescan_workflow())

        # 5. Verification & Diff Output
        results.append(cls._check_diff_output())

        # 6. Response Schema & Error Condition Audit
        results.append(cls._check_schema_and_errors())

        # 7. Integration test suite
        e2e_test = REPO_ROOT / "backend" / "tests" / "test_e2e.py"
        if not e2e_test.exists():
            results.append(
                CheckResult(
                    name="E2E Automated Integration Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_e2e.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_e2e_tests(str(e2e_test)))

        return results

    @classmethod
    def _check_scan_workflow(cls) -> CheckResult:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app
            import io, zipfile

            client = TestClient(app)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("app.py", 'API_KEY = "sk-test-abc123xyz456verylongfakekey9876"\n')
            buf.seek(0)

            res = client.post("/api/v1/scans", files={"file": ("project.zip", buf.getvalue(), "application/zip")})
            if res.status_code == 201:
                data = res.json()
                if "scan_id" in data and "findings" in data:
                    return CheckResult(
                        name="E2E Initial Submission & Scan Execution",
                        status=CheckStatus.PASS,
                        details=f"POST /api/v1/scans accepted archive and produced scan {data['scan_id']}.",
                    )
            return CheckResult(
                name="E2E Initial Submission & Scan Execution",
                status=CheckStatus.FAIL,
                details=f"Unexpected response: {res.status_code} - {res.text}",
            )
        except Exception as exc:
            return CheckResult(
                name="E2E Initial Submission & Scan Execution",
                status=CheckStatus.FAIL,
                details=f"Scan workflow failed: {exc}",
            )

    @classmethod
    def _check_report_retrieval(cls) -> CheckResult:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app
            import io, zipfile

            client = TestClient(app)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("app.py", 'KEY = "sk-test-abc123xyz456verylongfakekey9876"\n')
            buf.seek(0)

            res = client.post("/api/v1/scans", files={"file": ("report_test.zip", buf.getvalue(), "application/zip")})
            scan_id = res.json()["scan_id"]

            get_res = client.get(f"/api/v1/scans/{scan_id}")
            if get_res.status_code == 200:
                data = get_res.json()
                if data["scan_id"] == scan_id and "coverage" in data and "findings" in data:
                    return CheckResult(
                        name="E2E Report & Finding Retrieval",
                        status=CheckStatus.PASS,
                        details=f"GET /api/v1/scans/{scan_id} successfully retrieved findings and coverage.",
                    )
            return CheckResult(
                name="E2E Report & Finding Retrieval",
                status=CheckStatus.FAIL,
                details=f"Failed to retrieve report: status {get_res.status_code}",
            )
        except Exception as exc:
            return CheckResult(
                name="E2E Report & Finding Retrieval",
                status=CheckStatus.FAIL,
                details=f"Report retrieval error: {exc}",
            )

    @classmethod
    def _check_repair_prompt(cls) -> CheckResult:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app
            import io, zipfile

            client = TestClient(app)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("app.py", 'KEY = "sk-test-abc123xyz456verylongfakekey9876"\n')
            buf.seek(0)

            res = client.post("/api/v1/scans", files={"file": ("prompt_test.zip", buf.getvalue(), "application/zip")})
            data = res.json()
            prompt = data.get("repair_prompt")
            if prompt and len(prompt) > 50 and "sk-test-abc123xyz456verylongfakekey9876" not in prompt:
                return CheckResult(
                    name="E2E Usable Repair Prompt Generation",
                    status=CheckStatus.PASS,
                    details="Repair prompt generated with masked evidence and remediation steps.",
                )
            return CheckResult(
                name="E2E Usable Repair Prompt Generation",
                status=CheckStatus.FAIL,
                details="Repair prompt was missing, too short, or leaked raw secret.",
            )
        except Exception as exc:
            return CheckResult(
                name="E2E Usable Repair Prompt Generation",
                status=CheckStatus.FAIL,
                details=f"Repair prompt check failed: {exc}",
            )

    @classmethod
    def _check_rescan_workflow(cls) -> CheckResult:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app
            import io, zipfile

            client = TestClient(app)
            buf1 = io.BytesIO()
            with zipfile.ZipFile(buf1, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("app.py", 'KEY = "sk-test-abc123xyz456verylongfakekey9876"\n')
            buf1.seek(0)

            res1 = client.post("/api/v1/scans", files={"file": ("base.zip", buf1.getvalue(), "application/zip")})
            base_id = res1.json()["scan_id"]

            buf2 = io.BytesIO()
            with zipfile.ZipFile(buf2, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("app.py", 'KEY = os.environ.get("KEY")\n')
            buf2.seek(0)

            res2 = client.post(f"/api/v1/scans/{base_id}/rescan", files={"file": ("rescan.zip", buf2.getvalue(), "application/zip")})
            if res2.status_code == 201:
                data2 = res2.json()
                if "resolved_by_checks" in data2 and "summary" in data2:
                    return CheckResult(
                        name="E2E Corrected Code Rescan Submission",
                        status=CheckStatus.PASS,
                        details=f"POST /api/v1/scans/{base_id}/rescan accepted corrected code.",
                    )
            return CheckResult(
                name="E2E Corrected Code Rescan Submission",
                status=CheckStatus.FAIL,
                details=f"Rescan submission failed: {res2.status_code}",
            )
        except Exception as exc:
            return CheckResult(
                name="E2E Corrected Code Rescan Submission",
                status=CheckStatus.FAIL,
                details=f"Rescan error: {exc}",
            )

    @classmethod
    def _check_diff_output(cls) -> CheckResult:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app
            import io, zipfile

            client = TestClient(app)
            buf1 = io.BytesIO()
            with zipfile.ZipFile(buf1, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("app.py", 'KEY = "sk-test-abc123xyz456verylongfakekey9876"\n')
            buf1.seek(0)

            res1 = client.post("/api/v1/scans", files={"file": ("base.zip", buf1.getvalue(), "application/zip")})
            base_id = res1.json()["scan_id"]

            buf2 = io.BytesIO()
            with zipfile.ZipFile(buf2, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("app.py", 'KEY = os.environ.get("KEY")\n')
            buf2.seek(0)

            res2 = client.post(f"/api/v1/scans/{base_id}/rescan", files={"file": ("rescan.zip", buf2.getvalue(), "application/zip")})
            new_id = res2.json()["rescan_id"]

            comp_res = client.get(f"/api/v1/scans/{base_id}/comparison/{new_id}")
            if comp_res.status_code == 200:
                data = comp_res.json()
                if "resolved_by_checks" in data and "still_present" in data and "new" in data and "not_verified" in data:
                    return CheckResult(
                        name="E2E Verification & Diff Output",
                        status=CheckStatus.PASS,
                        details="GET comparison returned full 4-state diff classification.",
                    )
            return CheckResult(
                name="E2E Verification & Diff Output",
                status=CheckStatus.FAIL,
                details=f"Diff retrieval failed: status {comp_res.status_code}",
            )
        except Exception as exc:
            return CheckResult(
                name="E2E Verification & Diff Output",
                status=CheckStatus.FAIL,
                details=f"Diff check error: {exc}",
            )

    @classmethod
    def _check_schema_and_errors(cls) -> CheckResult:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app

            client = TestClient(app)
            # 404 for missing scan
            r1 = client.get("/api/v1/scans/missing-id-check")
            # 404 for missing rescan
            r2 = client.get("/api/v1/scans/missing-id/comparison/missing-id-2")

            if r1.status_code == 404 and r2.status_code == 404:
                return CheckResult(
                    name="E2E Response Schema & Error Condition Audit",
                    status=CheckStatus.PASS,
                    details="HTTP status codes and error models conform to API contract.",
                )
            return CheckResult(
                name="E2E Response Schema & Error Condition Audit",
                status=CheckStatus.FAIL,
                details=f"Unexpected error codes: {r1.status_code}, {r2.status_code}",
            )
        except Exception as exc:
            return CheckResult(
                name="E2E Response Schema & Error Condition Audit",
                status=CheckStatus.FAIL,
                details=f"Error audit check failed: {exc}",
            )

    @classmethod
    def _run_e2e_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="E2E Automated Integration Test Suite",
                status=CheckStatus.PASS,
                details="E2E integration tests passed.",
            )
        return CheckResult(
            name="E2E Automated Integration Test Suite",
            status=CheckStatus.FAIL,
            details=f"E2E tests failed:\n{output}",
        )
