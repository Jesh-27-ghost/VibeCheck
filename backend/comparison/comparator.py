"""Scan comparison and rescan diff engine (Phase 5).

Compares an initial baseline scan against a subsequent rescan, classifying findings into:
1. resolved_by_checks: Verified removed by an evaluated deterministic rule.
2. still_present: Persists across rescans.
3. new: Newly detected in the rescan.
4. not_verified: Could not be reliably proven resolved (e.g. check skipped, tool failed).
"""

from dataclasses import asdict, dataclass, field
import logging
from typing import Any, Dict, List, Optional, Set, Union

from backend.comparison.fingerprint import compute_finding_fingerprint

logger = logging.getLogger(__name__)


@dataclass
class ComparisonResult:
    """Structured outcome of comparing two scans."""

    base_scan_id: str
    rescan_id: str
    resolved_by_checks: List[Dict[str, Any]] = field(default_factory=list)
    still_present: List[Dict[str, Any]] = field(default_factory=list)
    new: List[Dict[str, Any]] = field(default_factory=list)
    not_verified: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    coverage_delta: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to standard JSON-compatible dict."""
        return {
            "base_scan_id": self.base_scan_id,
            "rescan_id": self.rescan_id,
            "status": "completed",
            "resolved_by_checks": self.resolved_by_checks,
            "still_present": self.still_present,
            "new": self.new,
            "not_verified": self.not_verified,
            "summary": self.summary,
            "coverage_delta": self.coverage_delta,
            "limitations": self.limitations,
        }


class ScanComparator:
    """Conservative diff engine for security scan results."""

    def compare(
        self,
        base_scan: Union[Dict[str, Any], Any],
        rescan: Union[Dict[str, Any], Any],
    ) -> ComparisonResult:
        """Compare two scans and classify findings honestly."""
        base_id = self._extract_id(base_scan, "base-scan")
        rescan_id = self._extract_id(rescan, "re-scan")

        base_findings = self._extract_findings(base_scan)
        rescan_findings = self._extract_findings(rescan)

        base_coverage = self._extract_coverage(base_scan)
        rescan_coverage = self._extract_coverage(rescan)

        # Evaluate coverage delta
        base_completed = set(base_coverage.get("completed", []))
        rescan_completed = set(rescan_coverage.get("completed", []))
        rescan_failed = set(rescan_coverage.get("failed", []))
        rescan_skipped = set(rescan_coverage.get("skipped", []))

        rules_in_both = sorted(base_completed.intersection(rescan_completed))
        rules_added = sorted(rescan_completed - base_completed)
        rules_dropped = sorted(base_completed - rescan_completed)

        coverage_notes = []
        is_comparable = True
        if rules_dropped:
            coverage_notes.append(
                f"Rules evaluated in baseline but not in rescan: {', '.join(rules_dropped)}."
            )
            is_comparable = False
        if rescan_failed:
            coverage_notes.append(
                f"Some rules failed during rescan execution: {', '.join(rescan_failed)}."
            )
            is_comparable = False

        coverage_delta = {
            "rules_in_both": rules_in_both,
            "rules_added": rules_added,
            "rules_dropped": rules_dropped,
            "comparable": is_comparable,
            "notes": coverage_notes,
        }

        # Build rescan index by fingerprint
        rescan_by_fp: Dict[str, List[Dict[str, Any]]] = {}
        for f in rescan_findings:
            fp = compute_finding_fingerprint(f)
            rescan_by_fp.setdefault(fp, []).append(f)

        resolved_by_checks: List[Dict[str, Any]] = []
        still_present: List[Dict[str, Any]] = []
        not_verified: List[Dict[str, Any]] = []
        matched_rescan_fps: Set[str] = set()

        for bf in base_findings:
            bf_dict = self._ensure_dict(bf)
            bf_fp = compute_finding_fingerprint(bf_dict)
            rule_id = str(bf_dict.get("rule_id", ""))

            # Honest resolution check:
            # Did the rule that produced this finding run successfully in rescan?
            rule_completed = self._rule_in_set(rule_id, rescan_completed)
            rule_failed = self._rule_in_set(rule_id, rescan_failed)
            rule_skipped = self._rule_in_set(rule_id, rescan_skipped)

            rule_failed_or_skipped = (
                rule_failed
                or rule_skipped
                or (rescan_completed and not rule_completed)
            )

            # Check if matching finding exists in rescan
            matching_rf_list = rescan_by_fp.get(bf_fp, [])

            if matching_rf_list:
                # Finding is still present
                still_present.append(bf_dict)
                matched_rescan_fps.add(bf_fp)
            else:
                # Finding is absent in rescan
                if rule_failed_or_skipped:
                    # Honest: cannot verify resolution if rule didn't run or failed!
                    unverified_finding = dict(bf_dict)
                    unverified_finding["verification_note"] = (
                        f"Check '{rule_id}' was not evaluated or failed in rescan; cannot confirm resolution."
                    )
                    not_verified.append(unverified_finding)
                else:
                    # Successfully resolved by deterministic check
                    resolved_by_checks.append(bf_dict)

        # Check for new findings in rescan
        new_findings: List[Dict[str, Any]] = []
        for rf in rescan_findings:
            rf_dict = self._ensure_dict(rf)
            rf_fp = compute_finding_fingerprint(rf_dict)
            if rf_fp not in matched_rescan_fps:
                # Also double check against baseline
                base_matching = any(
                    compute_finding_fingerprint(b) == rf_fp for b in base_findings
                )
                if not base_matching:
                    new_findings.append(rf_dict)

        summary = {
            "resolved_count": len(resolved_by_checks),
            "still_present_count": len(still_present),
            "new_count": len(new_findings),
            "not_verified_count": len(not_verified),
            "total_baseline": len(base_findings),
            "total_rescan": len(rescan_findings),
        }

        limitations = [
            "Resolution verification applies strictly to deterministic rules evaluated in both scans.",
            "Absence of findings is not proof that the application is completely secure.",
        ]
        if not is_comparable:
            limitations.append(
                "Coverage changed between scans; comparison may be incomplete."
            )

        return ComparisonResult(
            base_scan_id=base_id,
            rescan_id=rescan_id,
            resolved_by_checks=resolved_by_checks,
            still_present=still_present,
            new=new_findings,
            not_verified=not_verified,
            summary=summary,
            coverage_delta=coverage_delta,
            limitations=limitations,
        )

    @staticmethod
    def _extract_id(scan: Any, fallback: str) -> str:
        if isinstance(scan, dict):
            return str(scan.get("scan_id", fallback))
        return str(getattr(scan, "scan_id", fallback))

    @staticmethod
    def _extract_findings(scan: Any) -> List[Any]:
        if isinstance(scan, dict):
            return scan.get("findings", []) or []
        return getattr(scan, "findings", []) or []

    @staticmethod
    def _extract_coverage(scan: Any) -> Dict[str, Any]:
        if isinstance(scan, dict):
            cov = scan.get("coverage", {})
            if isinstance(cov, dict):
                return cov
            return getattr(cov, "__dict__", {})
        cov = getattr(scan, "coverage", {})
        if isinstance(cov, dict):
            return cov
        return getattr(cov, "__dict__", {})

    @staticmethod
    def _rule_in_set(rule_id: str, rule_set: Set[str]) -> bool:
        """Check if rule_id matches any rule identifier in rule_set.
        
        Handles exact matches as well as 'rule_id:category' format.
        """
        if not rule_set:
            return False
        clean_id = rule_id.strip()
        for item in rule_set:
            if item == clean_id:
                return True
            if item.split(":")[0] == clean_id:
                return True
        return False

    @staticmethod
    def _ensure_dict(finding: Any) -> Dict[str, Any]:
        if isinstance(finding, dict):
            return dict(finding)
        if hasattr(finding, "model_dump"):
            return finding.model_dump()
        if hasattr(finding, "dict"):
            return finding.dict()
        if hasattr(finding, "__dict__"):
            return dict(finding.__dict__)
        return {"raw": str(finding)}


def compare_scans(
    base_scan: Union[Dict[str, Any], Any],
    rescan: Union[Dict[str, Any], Any],
) -> ComparisonResult:
    """Convenience function to compare two scans using ScanComparator."""
    comparator = ScanComparator()
    return comparator.compare(base_scan, rescan)
