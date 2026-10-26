"""Core scanner engine for VibeShield.

Performs deterministic, rule-based static analysis on extracted project
source files. This module:

- Never executes submitted code.
- Masks secret values in all findings before they are returned.
- Records failed, skipped, and unsupported checks honestly.
- Does not claim a clean result when the scanner itself encounters an error.

Public interface
----------------
scan_project(project_path: str) -> dict

The returned dict is JSON-serialisable and matches the ScanResponse contract.
"""

import logging
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from backend.scanners.masking import build_evidence_line, ensure_no_raw_secrets
from backend.scanners.rules import ALL_RULES, Rule

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File-type configuration
# ---------------------------------------------------------------------------

# Extensions the scanner will read and analyse
SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".html",
        ".htm",
        ".php",
        ".rb",
        ".go",
        ".java",
        ".cs",
        ".env",
        ".cfg",
        ".ini",
        ".conf",
        ".yaml",
        ".yml",
        ".toml",
        ".json",
        ".sh",
        ".bash",
        ".zsh",
        ".xml",
        ".properties",
        ".txt",
        ".md",
        ".sql",
    }
)

# Maximum bytes to read per file (avoids reading huge binary blobs)
MAX_FILE_READ_BYTES = 1_048_576  # 1 MB

# Directories excluded from scanning
IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".next",
        ".nuxt",
        ".pytest_cache",
        ".mypy_cache",
    }
)


# ---------------------------------------------------------------------------
# Result data structures
# ---------------------------------------------------------------------------


@dataclass
class ScanFinding:
    """A single normalised security finding from the scanner."""

    id: str
    rule_id: str
    category: str
    title: str
    severity: str
    confidence: str
    status: str
    file_path: str
    line_start: int
    line_end: int
    evidence: str          # already masked for secret rules
    impact: str
    recommendation: str
    verification_steps: list[str] = field(default_factory=list)


@dataclass
class ScanCoverageDetail:
    """Coverage breakdown for the scan."""

    completed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Top-level result returned by the scanner."""

    findings: list[ScanFinding] = field(default_factory=list)
    files_scanned: int = 0
    total_lines: int = 0
    coverage: ScanCoverageDetail = field(default_factory=ScanCoverageDetail)
    limitations: list[str] = field(default_factory=list)
    scanner_error: Optional[str] = None  # Set when scanner itself fails


# ---------------------------------------------------------------------------
# Scanner engine
# ---------------------------------------------------------------------------


class ScannerEngine:
    """Applies all registered rules to source files in a project workspace."""

    # Unsupported check types the scanner explicitly acknowledges it cannot do
    _UNSUPPORTED = [
        "runtime_authentication_testing",
        "dependency_vulnerability_audit",
        "deployed_url_passive_scan",
        "ast_based_data_flow_analysis",
    ]

    def scan(self, project_path: str) -> ScanResult:
        """Run all rules on all eligible source files under project_path.

        Args:
            project_path: Absolute path to the extracted project workspace.

        Returns:
            ScanResult — never raises; scanner errors are captured in
            ScanResult.scanner_error so the caller can report partial coverage
            rather than a false clean scan.
        """
        result = ScanResult()
        result.coverage.unsupported = list(self._UNSUPPORTED)
        result.limitations = [
            "This scan does not prove the application is completely secure.",
            "Only static pattern matching is performed; runtime behaviour is not evaluated.",
            "Secret detection uses heuristic patterns and may produce false positives.",
            "Dependency vulnerabilities, deployed URL scanning, and data-flow analysis are not supported in this build.",
        ]

        root = Path(project_path)
        if not root.exists() or not root.is_dir():
            result.scanner_error = f"Project path does not exist or is not a directory: {project_path}"
            result.coverage.failed.append("file_system_access")
            logger.error("Scanner: project path not found: %s", project_path)
            return result

        # Collect scannable files
        try:
            source_files = self._collect_files(root)
        except Exception as exc:
            result.scanner_error = "File collection failed; scan aborted."
            result.coverage.failed.append("file_collection")
            logger.error("Scanner: file collection error: %s", exc)
            return result

        # Track known raw secret values for final sanitisation pass
        raw_secrets: list[str] = []

        for rule in ALL_RULES:
            rule_completed = True
            try:
                for source_file in source_files:
                    try:
                        findings = self._scan_file(source_file, root, rule, raw_secrets)
                        result.findings.extend(findings)
                    except Exception as exc:
                        # File-level error: record failure but continue other files
                        logger.warning(
                            "Scanner: error processing %s with rule %s: %s",
                            source_file,
                            rule.rule_id,
                            exc,
                        )
                        rule_completed = False
            except Exception as exc:
                rule_completed = False
                logger.error("Scanner: rule %s execution failed: %s", rule.rule_id, exc)

            if rule_completed:
                rule_name = f"{rule.rule_id}:{rule.category}"
                if rule_name not in result.coverage.completed:
                    result.coverage.completed.append(rule_name)
            else:
                failed_name = f"{rule.rule_id}:{rule.category}"
                if failed_name not in result.coverage.failed:
                    result.coverage.failed.append(failed_name)

        # Deduplicate findings (same rule + file + line)
        result.findings = self._deduplicate(result.findings)

        # Final safety pass: ensure no raw secret appears in any evidence string
        if raw_secrets:
            for finding in result.findings:
                finding.evidence = ensure_no_raw_secrets(finding.evidence, raw_secrets)

        result.files_scanned = len(source_files)
        result.total_lines = sum(self._count_lines(f) for f in source_files)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_files(self, root: Path) -> list[Path]:
        """Walk project tree and return all scannable files."""
        files: list[Path] = []
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            # Skip ignored directories anywhere in the tree
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            if path.suffix.lower() in SCANNABLE_EXTENSIONS:
                files.append(path)
        return sorted(files)

    def _scan_file(
        self,
        file_path: Path,
        root: Path,
        rule: Rule,
        raw_secrets: list[str],
    ) -> list[ScanFinding]:
        """Apply a single rule to one file and return any findings."""
        findings: list[ScanFinding] = []

        try:
            content = file_path.read_bytes()[:MAX_FILE_READ_BYTES].decode(
                "utf-8", errors="replace"
            )
        except (OSError, PermissionError) as exc:
            logger.warning("Scanner: cannot read file %s: %s", file_path, exc)
            return findings

        lines = content.splitlines()
        relative_path = file_path.relative_to(root).as_posix()

        for match in rule.pattern.finditer(content):
            # Determine which line the match falls on (1-indexed)
            match_start = match.start()
            line_number = content[:match_start].count("\n") + 1
            line_index = line_number - 1
            raw_line = lines[line_index] if line_index < len(lines) else ""

            # Mask secret value before storing evidence
            evidence = build_evidence_line(raw_line, match, rule.is_secret_rule)

            # Collect raw secret for final sanitisation pass (not stored in finding)
            if rule.is_secret_rule:
                try:
                    secret_val = match.group(1)
                except IndexError:
                    secret_val = match.group(0)
                if secret_val and secret_val not in raw_secrets:
                    raw_secrets.append(secret_val)

            finding = ScanFinding(
                id=f"{rule.rule_id}-{uuid.uuid4().hex[:8]}",
                rule_id=rule.rule_id,
                category=rule.category,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                status="open",
                file_path=relative_path,
                line_start=line_number,
                line_end=line_number,
                evidence=evidence,
                impact=rule.impact,
                recommendation=rule.recommendation,
                verification_steps=list(rule.verification_steps),
            )
            findings.append(finding)

        return findings

    def _deduplicate(self, findings: list[ScanFinding]) -> list[ScanFinding]:
        """Remove exact duplicate findings (same rule_id + file + line_start)."""
        seen: set[tuple] = set()
        unique: list[ScanFinding] = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_start)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _count_lines(self, file_path: Path) -> int:
        """Count newlines in a file without executing it."""
        try:
            content = file_path.read_bytes()[:MAX_FILE_READ_BYTES]
            return content.count(b"\n") + 1
        except OSError:
            return 0


# ---------------------------------------------------------------------------
# Public function — stable interface for API integration
# ---------------------------------------------------------------------------


def run_scanners(project_path: str) -> dict:
    """Run the VibeShield scanner suite on an extracted project.

    This is the stable interface consumed by the API layer. It never
    executes submitted code and always returns a JSON-serialisable dict.

    Args:
        project_path: Absolute path to the staged project source directory.

    Returns:
        A JSON-serialisable dict with keys:
            findings        - list of finding dicts
            files_scanned   - int
            total_lines     - int
            coverage        - dict (completed, failed, skipped, unsupported)
            limitations     - list[str]
            scanner_error   - str | None
    """
    engine = ScannerEngine()
    result = engine.scan(project_path)

    findings_list = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "category": f.category,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "location": {
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "snippet": f.evidence,
            },
            "evidence": f.evidence,
            "impact": f.impact,
            "recommendation": f.recommendation,
            "verification_steps": f.verification_steps,
        }
        for f in result.findings
    ]

    return {
        "findings": findings_list,
        "files_scanned": result.files_scanned,
        "total_lines": result.total_lines,
        "coverage": {
            "completed": result.coverage.completed,
            "failed": result.coverage.failed,
            "skipped": result.coverage.skipped,
            "unsupported": result.coverage.unsupported,
        },
        "limitations": result.limitations,
        "scanner_error": result.scanner_error,
    }
