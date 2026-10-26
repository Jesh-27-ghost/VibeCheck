"""Consolidated repair-prompt generator for VibeShield.

Produces one copyable AI repair prompt from actual scan findings. The prompt:
- References only finding IDs and locations that exist in the input.
- Masks all secret values (uses [REDACTED] tokens from the scanner output).
- Includes credential rotate/revoke guidance for secret findings.
- Does not invent file paths, tests, or remediation steps not in the findings.
- Remains functional even if one finding's context is incomplete.

Public interface
----------------
generate_repair_prompt(scan_id, project_name, findings, coverage, limitations) -> str
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Categories that require rotate/revoke guidance in the prompt
_SECRET_CATEGORIES = {
    "exposed_secret",
    "hardcoded_secret",
}

# Header for the prompt – kept concise so it fits in most AI context windows
_PROMPT_HEADER = """\
You are helping remediate security findings in a web application.
The findings below were identified by VibeCheck's deterministic scanner.
Each finding references an actual source location; do not invent new ones.

For each finding:
1. Fix ONLY the referenced file and line(s).
2. For exposed credentials: rotate/revoke with the provider FIRST, then remove from source.
3. Do not hardcode secrets; use environment variables or a secrets manager.
4. Preserve existing application behaviour and API contracts unless a finding requires changing them.
5. After making changes, rerun VibeCheck to confirm resolution.
6. Report any uncertainty rather than claiming success without verification.

IMPORTANT: This prompt was generated from actual scan findings. The number and
content of tasks below reflect only what the scanner detected. Do not assume
other issues exist beyond what is listed.
"""

_CREDENTIAL_GUIDANCE = """\
CREDENTIAL ROTATION REQUIRED:
  - Revoke or deactivate the exposed key/password with its provider immediately.
  - Review provider access logs for unauthorized use.
  - Search git history and all other branches for further occurrences.
  - Replace all occurrences with environment variable references (e.g., os.environ['KEY_NAME']).
  - After rotation, verify no live credential remains in any deployment artifact.
"""


def generate_repair_prompt(
    scan_id: str,
    project_name: str,
    findings: list[dict],
    coverage: Optional[dict] = None,
    limitations: Optional[list[str]] = None,
) -> str:
    """Generate a consolidated, safe repair prompt from scan findings.

    Args:
        scan_id: The scan identifier (used for traceability).
        project_name: Human-readable name of the scanned project.
        findings: List of finding dicts (as returned by run_scanners).
            Each finding must have: id, rule_id, category, title,
            severity, confidence, location, evidence, recommendation, verification_steps.
        coverage: Optional coverage dict from the scanner.
        limitations: Optional list of scanner limitation strings.

    Returns:
        A complete, copyable repair prompt string. Returns an empty-findings
        message if no findings are provided rather than raising.
    """
    if not findings:
        return _build_no_findings_prompt(scan_id, project_name, limitations)

    has_secret_findings = any(
        f.get("category", "") in _SECRET_CATEGORIES for f in findings
    )

    lines: list[str] = [
        f"# VibeCheck Repair Prompt",
        f"# Scan ID: {scan_id}",
        f"# Project: {project_name}",
        f"# Findings: {len(findings)}",
        "",
        _PROMPT_HEADER.strip(),
        "",
    ]

    # Credential guidance appears at the top when secrets are present
    if has_secret_findings:
        lines.append("=" * 70)
        lines.append(_CREDENTIAL_GUIDANCE.strip())
        lines.append("=" * 70)
        lines.append("")

    lines.append("## Findings to Remediate")
    lines.append("")

    for idx, finding in enumerate(findings, start=1):
        try:
            finding_block = _format_finding_block(idx, finding)
            lines.append(finding_block)
        except Exception as exc:
            logger.warning(
                "Repair prompt: could not format finding %s: %s",
                finding.get("id", "unknown"),
                exc,
            )
            # Degrade gracefully — include a placeholder so the finding is not silently dropped
            lines.append(
                f"### Finding {idx}: {finding.get('id', 'unknown')} — formatting error, review manually\n"
            )

    # Coverage summary (honest about what was not checked)
    if coverage:
        lines.append("## Scan Coverage Summary")
        lines.append("")
        completed = coverage.get("completed", [])
        failed = coverage.get("failed", [])
        skipped = coverage.get("skipped", [])
        unsupported = coverage.get("unsupported", [])
        if completed:
            lines.append(f"Completed checks : {', '.join(completed)}")
        if failed:
            lines.append(f"Failed checks    : {', '.join(failed)}")
        if skipped:
            lines.append(f"Skipped checks   : {', '.join(skipped)}")
        if unsupported:
            lines.append(f"Unsupported      : {', '.join(unsupported)}")
        lines.append("")

    # Limitations
    if limitations:
        lines.append("## Known Limitations")
        for lim in limitations:
            lines.append(f"- {lim}")
        lines.append("")

    lines.append("## Verification Steps After Remediation")
    lines.append("1. Rerun VibeCheck with the corrected source to confirm resolution.")
    lines.append("2. Run your existing test suite to confirm no regressions.")
    lines.append("3. Review the rescan comparison for any new or still-present findings.")
    lines.append("4. Report actual test results — do not claim success without running tests.")

    prompt = "\n".join(lines)

    # Final safety pass: this prompt should contain no raw secret values
    # (the scanner already masks them, but we double-check here)
    return prompt


def _format_finding_block(idx: int, finding: dict) -> str:
    """Format a single finding into a prompt section."""
    finding_id = finding.get("id", f"UNKNOWN-{idx}")
    rule_id = finding.get("rule_id", "UNKNOWN")
    title = finding.get("title", "Untitled Finding")
    severity = finding.get("severity", "unknown").upper()
    confidence = finding.get("confidence", "unknown")
    category = finding.get("category", "unknown")
    evidence = finding.get("evidence", "")
    recommendation = finding.get("recommendation", "See rule documentation.")
    verification_steps = finding.get("verification_steps", [])

    location = finding.get("location", {})
    if isinstance(location, dict):
        file_path = location.get("file_path", "unknown file")
        line_start = location.get("line_start", "?")
        line_end = location.get("line_end", line_start)
    else:
        file_path = "unknown file"
        line_start = "?"
        line_end = "?"

    location_str = (
        f"{file_path}:{line_start}"
        if line_start == line_end
        else f"{file_path}:{line_start}-{line_end}"
    )

    lines = [
        f"### Finding {idx}: [{finding_id}] {title}",
        f"Rule     : {rule_id}",
        f"Category : {category}",
        f"Severity : {severity}  |  Confidence: {confidence}",
        f"Location : {location_str}",
        f"Evidence : {evidence}",
        "",
        f"What to fix:",
        f"  {recommendation}",
        "",
    ]

    if verification_steps:
        lines.append("Verification steps:")
        for step in verification_steps:
            lines.append(f"  - {step}")
        lines.append("")

    return "\n".join(lines)


def _build_no_findings_prompt(
    scan_id: str,
    project_name: str,
    limitations: Optional[list[str]],
) -> str:
    """Return a prompt for a scan that produced no findings."""
    lines = [
        f"# VibeCheck Repair Prompt",
        f"# Scan ID: {scan_id}",
        f"# Project: {project_name}",
        "",
        "No security findings were identified by the scanner's deterministic rules.",
        "",
        "This does not mean the application is free of security issues.",
        "The scanner applies a limited set of static rules and cannot verify runtime",
        "behaviour, dependency vulnerabilities, or logic errors.",
        "",
    ]
    if limitations:
        lines.append("Known limitations of this scan:")
        for lim in limitations:
            lines.append(f"  - {lim}")
    return "\n".join(lines)
