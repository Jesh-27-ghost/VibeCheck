"""Pydantic schemas for rescan diff and verification comparison (Phase 5)."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.finding import Finding


class ComparisonStatus(str, Enum):
    """The four conservative comparison classifications."""

    RESOLVED = "resolved_by_checks"
    STILL_PRESENT = "still_present"
    NEW = "new"
    NOT_VERIFIED = "not_verified"


class ComparisonSummary(BaseModel):
    """Numerical summary of comparison results."""

    resolved_count: int = Field(0, description="Findings resolved by deterministic checks")
    still_present_count: int = Field(0, description="Findings still present in rescan")
    new_count: int = Field(0, description="New findings introduced in rescan")
    not_verified_count: int = Field(0, description="Findings where resolution could not be verified")
    total_baseline: int = Field(0, description="Total findings in original baseline scan")
    total_rescan: int = Field(0, description="Total findings in rescan")


class CoverageDelta(BaseModel):
    """Coverage changes between baseline and rescan."""

    rules_in_both: List[str] = Field(default_factory=list)
    rules_added: List[str] = Field(default_factory=list)
    rules_dropped: List[str] = Field(default_factory=list)
    comparable: bool = Field(True, description="True if coverage is sufficiently comparable")
    notes: List[str] = Field(default_factory=list)


class ComparisonResponse(BaseModel):
    """Full scan comparison response payload."""

    base_scan_id: str = Field(..., description="Original baseline scan identifier")
    rescan_id: str = Field(..., description="Subsequent rescan identifier")
    status: str = Field("completed", description="Status of the comparison")
    resolved_by_checks: List[Finding] = Field(default_factory=list, description="Findings verified as resolved")
    still_present: List[Finding] = Field(default_factory=list, description="Findings still detected in rescan")
    new: List[Finding] = Field(default_factory=list, description="New findings appearing in rescan")
    not_verified: List[Finding] = Field(default_factory=list, description="Findings that cannot be verified honestly")
    summary: ComparisonSummary = Field(default_factory=ComparisonSummary)
    coverage_delta: CoverageDelta = Field(default_factory=CoverageDelta)
    limitations: List[str] = Field(default_factory=list, description="Honest disclaimers and scope limitations")
