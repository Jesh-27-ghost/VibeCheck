"""Rescan diff and verification comparison module for VibeShield (Phase 5)."""

from backend.comparison.comparator import (
    ComparisonResult,
    ScanComparator,
    compare_scans,
)
from backend.comparison.fingerprint import (
    compute_finding_fingerprint,
    normalize_evidence,
    normalize_file_path,
)

__all__ = [
    "ComparisonResult",
    "ScanComparator",
    "compare_scans",
    "compute_finding_fingerprint",
    "normalize_evidence",
    "normalize_file_path",
]
