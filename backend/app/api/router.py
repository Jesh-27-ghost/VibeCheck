"""API router definition for VibeShield endpoints — Phase 5 with Rescan & Comparison."""

import io
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import zipfile

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.intake.exceptions import IntakeError
from backend.app.intake.service import IntakeService
from backend.app.schemas.comparison import (
    ComparisonResponse,
    ComparisonSummary,
    CoverageDelta,
)
from backend.app.schemas.finding import Finding, FindingLocation
from backend.app.schemas.scan import ScanCoverage, ScanResponse
from backend.comparison import ComparisonResult, compare_scans
from backend.remediation import generate_repair_prompt
from backend.scanners import run_scanners

logger = logging.getLogger(__name__)

api_router = APIRouter()
intake_service = IntakeService()

# In-memory scan store for baseline persistence and rescan comparisons
SCAN_STORE: Dict[str, ScanResponse] = {}
RAW_SCAN_STORE: Dict[str, Dict[str, Any]] = {}
COMPARISON_STORE: Dict[Tuple[str, str], ComparisonResponse] = {}


def _to_finding_model(raw: Any) -> Optional[Finding]:
    """Convert a finding dict or model into a valid Finding schema instance."""
    if isinstance(raw, Finding):
        return raw
    if not isinstance(raw, dict):
        return None
    try:
        loc = raw.get("location", {})
        if isinstance(loc, FindingLocation):
            loc_model = loc
        elif isinstance(loc, dict):
            loc_model = FindingLocation(
                file_path=loc.get("file_path") or loc.get("file") or "unknown",
                line_start=loc.get("line_start"),
                line_end=loc.get("line_end"),
                snippet=loc.get("snippet"),
            )
        else:
            loc_model = FindingLocation(file_path="unknown")

        return Finding(
            id=str(raw.get("id", "UNKNOWN")),
            rule_id=str(raw.get("rule_id", "UNKNOWN")),
            category=str(raw.get("category", "security_finding")),
            title=str(raw.get("title", "Untitled Finding")),
            severity=str(raw.get("severity", "medium")),
            confidence=str(raw.get("confidence", "medium")),
            status=str(raw.get("status", "open")),
            location=loc_model,
            evidence=raw.get("evidence", {}),
            impact=str(raw.get("impact", "")),
            recommendation=str(raw.get("recommendation", "")),
            verification_steps=raw.get("verification_steps", []),
        )
    except Exception as exc:
        logger.warning("Failed to parse finding: %s", exc)
        return None


def _build_comparison_response(comp: ComparisonResult) -> ComparisonResponse:
    """Build a Pydantic ComparisonResponse from a ComparisonResult dataclass."""
    def parse_list(items: List[Any]) -> List[Finding]:
        res = []
        for it in items:
            fm = _to_finding_model(it)
            if fm:
                res.append(fm)
        return res

    cd = comp.coverage_delta or {}
    cov_delta = CoverageDelta(
        rules_in_both=cd.get("rules_in_both", []),
        rules_added=cd.get("rules_added", []),
        rules_dropped=cd.get("rules_dropped", []),
        comparable=cd.get("comparable", True),
        notes=cd.get("notes", []),
    )

    s = comp.summary or {}
    summary = ComparisonSummary(
        resolved_count=s.get("resolved_count", 0),
        still_present_count=s.get("still_present_count", 0),
        new_count=s.get("new_count", 0),
        not_verified_count=s.get("not_verified_count", 0),
        total_baseline=s.get("total_baseline", 0),
        total_rescan=s.get("total_rescan", 0),
    )

    return ComparisonResponse(
        base_scan_id=comp.base_scan_id,
        rescan_id=comp.rescan_id,
        status="completed",
        resolved_by_checks=parse_list(comp.resolved_by_checks),
        still_present=parse_list(comp.still_present),
        new=parse_list(comp.new),
        not_verified=parse_list(comp.not_verified),
        summary=summary,
        coverage_delta=cov_delta,
        limitations=comp.limitations,
    )


async def _execute_scan(file: UploadFile) -> Tuple[ScanResponse, Dict[str, Any]]:
    """Helper to process upload, run scanner, generate repair prompt, and format response."""
    # --- Intake ---
    try:
        scan_id, project_name, manifest, source_dir = await intake_service.stage_upload(file)
    except IntakeError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        )
    except Exception:
        logger.exception("Unexpected error during archive intake")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during archive intake.",
        )

    # --- Scanner ---
    scanner_result: Optional[dict] = None
    try:
        scanner_result = run_scanners(str(source_dir))
    except Exception as exc:
        logger.error("Scanner raised an unhandled exception for scan %s: %s", scan_id, exc)
        scanner_result = {
            "findings": [],
            "files_scanned": manifest.total_files,
            "total_lines": manifest.total_lines,
            "coverage": {
                "completed": [],
                "failed": ["scanner_execution"],
                "skipped": [],
                "unsupported": [],
            },
            "limitations": ["Scanner encountered an unhandled error; results are incomplete."],
            "scanner_error": "Scanner execution failed — findings may be incomplete.",
        }

    raw_findings = scanner_result.get("findings", [])
    coverage_data = scanner_result.get("coverage", {})
    limitations = scanner_result.get("limitations", [])
    scanner_error = scanner_result.get("scanner_error")

    if scanner_error:
        limitations = [f"[Scanner Error] {scanner_error}"] + limitations

    # --- Normalise findings into schema ---
    findings: List[Finding] = []
    for raw in raw_findings:
        fm = _to_finding_model(raw)
        if fm:
            findings.append(fm)

    # --- Repair prompt ---
    repair_prompt: Optional[str] = None
    try:
        repair_prompt = generate_repair_prompt(
            scan_id=scan_id,
            project_name=project_name,
            findings=raw_findings,
            coverage=coverage_data,
            limitations=limitations,
        )
    except Exception as exc:
        logger.error("Repair prompt generation failed for scan %s: %s", scan_id, exc)
        repair_prompt = None

    # --- Build coverage schema ---
    coverage = ScanCoverage(
        files_scanned=scanner_result.get("files_scanned", manifest.total_files),
        total_lines=scanner_result.get("total_lines", manifest.total_lines),
        rules_evaluated=len(coverage_data.get("completed", [])),
        skipped_files=manifest.skipped_files,
        completed=coverage_data.get("completed", []),
        failed=coverage_data.get("failed", []),
        skipped=coverage_data.get("skipped", []),
        unsupported=coverage_data.get("unsupported", []),
    )

    scan_status = "failed" if scanner_error else ("completed" if findings is not None else "pending")

    response = ScanResponse(
        scan_id=scan_id,
        status=scan_status,
        project=project_name,
        coverage=coverage,
        findings=findings,
        repair_prompt=repair_prompt,
        limitations=limitations,
    )

    raw_data = {
        "scan_id": scan_id,
        "project_name": project_name,
        "manifest": manifest,
        "findings": raw_findings,
        "coverage": coverage_data,
        "limitations": limitations,
        "scanner_error": scanner_error,
    }

    # Store in memory for retrieval and comparison
    SCAN_STORE[scan_id] = response
    RAW_SCAN_STORE[scan_id] = raw_data

    return response, raw_data


@api_router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload website source code for deterministic security review",
    tags=["Scans"],
)
async def create_scan(file: UploadFile = File(...)) -> ScanResponse:
    """Accept a ZIP archive, validate safety constraints, run deterministic scanner, return findings."""
    response, _ = await _execute_scan(file)
    return response


@api_router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve an existing scan report by scan ID",
    tags=["Scans"],
)
async def get_scan(scan_id: str) -> ScanResponse:
    """Retrieve scan status, findings, coverage, and repair prompt for a previous scan."""
    scan = SCAN_STORE.get(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return scan


@api_router.post(
    "/scans/{scan_id}/rescan",
    response_model=ComparisonResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload corrected code for rescan and immediate baseline comparison",
    tags=["Scans", "Comparison"],
)
async def rescan_project(
    scan_id: str,
    file: UploadFile = File(...),
) -> ComparisonResponse:
    """Accept corrected source archive, run scan, and compare against base scan."""
    base_scan = SCAN_STORE.get(scan_id)
    if not base_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline scan '{scan_id}' not found.",
        )

    # Run the new rescan
    rescan_response, _ = await _execute_scan(file)
    new_scan_id = rescan_response.scan_id

    # Run comparison
    comparison_result = compare_scans(base_scan, rescan_response)
    resp = _build_comparison_response(comparison_result)

    # Cache comparison
    COMPARISON_STORE[(scan_id, new_scan_id)] = resp
    return resp


@api_router.get(
    "/scans/{scan_id}/comparison/{new_scan_id}",
    response_model=ComparisonResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve comparison between baseline and rescan",
    tags=["Comparison"],
)
async def get_comparison(
    scan_id: str,
    new_scan_id: str,
) -> ComparisonResponse:
    """Retrieve diff comparison categories between two existing scans."""
    if scan_id not in SCAN_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline scan '{scan_id}' not found.",
        )
    if new_scan_id not in SCAN_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rescan '{new_scan_id}' not found.",
        )

    # Check cache
    cached = COMPARISON_STORE.get((scan_id, new_scan_id))
    if cached:
        return cached

    # Compute comparison
    comparison_result = compare_scans(SCAN_STORE[scan_id], SCAN_STORE[new_scan_id])
    resp = _build_comparison_response(comparison_result)
    COMPARISON_STORE[(scan_id, new_scan_id)] = resp
    return resp


@api_router.post(
    "/demo/scan-sample",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Run demo scan directly on vulnerable or corrected sample",
    tags=["Demo"],
)
async def scan_demo_sample(sample_type: str = "vulnerable") -> ScanResponse:
    """Run an automated demo scan directly using the bundled sample fixtures."""
    target_dir = REPO_ROOT / "samples" / ("vulnerable" if sample_type == "vulnerable" else "corrected")
    if not target_dir.exists():
        raise HTTPException(status_code=404, detail=f"Sample '{sample_type}' directory not found.")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in target_dir.rglob("*"):
            if file_path.is_file() and not file_path.name.startswith("."):
                rel_path = file_path.relative_to(target_dir)
                zf.write(file_path, str(rel_path))
    buf.seek(0)

    upload_file = UploadFile(filename=f"demo-{sample_type}.zip", file=buf)
    resp, _ = await _execute_scan(upload_file)
    return resp


@api_router.post(
    "/demo/rescan-sample/{scan_id}",
    response_model=ComparisonResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Run demo rescan on corrected sample against baseline",
    tags=["Demo"],
)
async def rescan_demo_sample(scan_id: str) -> ComparisonResponse:
    """Run an automated rescan with the corrected fixture against an existing baseline scan."""
    if scan_id not in SCAN_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline scan '{scan_id}' not found.",
        )

    target_dir = REPO_ROOT / "samples" / "corrected"
    if not target_dir.exists():
        raise HTTPException(status_code=404, detail="Corrected sample directory not found.")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in target_dir.rglob("*"):
            if file_path.is_file() and not file_path.name.startswith("."):
                rel_path = file_path.relative_to(target_dir)
                zf.write(file_path, str(rel_path))
    buf.seek(0)

    upload_file = UploadFile(filename="demo-corrected.zip", file=buf)
    return await rescan_project(scan_id, upload_file)
