"""Secret value masking utilities for VibeShield.

All secret-like values must be masked before any finding or log entry
leaves the scanner. This module provides the canonical masking function
used across scanners, remediation, and logging paths.
"""

import re
from typing import Optional

# Replacement token visible in evidence output
MASKED_TOKEN = "[REDACTED]"

# Maximum number of characters from the start/end of a secret to show as context.
# Set to 0 for complete replacement (safest).
_CONTEXT_CHARS = 0


def mask_secret(raw_value: str, context_chars: int = _CONTEXT_CHARS) -> str:
    """Return a redacted representation of a secret value.

    Args:
        raw_value: The original secret string that must not appear in output.
        context_chars: Optional number of chars from the start/end to retain
            as context (e.g., 2 → "AB[REDACTED]XY"). Defaults to 0 (full mask).

    Returns:
        A masked string that conveys the location without revealing the secret.
    """
    if not raw_value:
        return MASKED_TOKEN
    if context_chars <= 0 or len(raw_value) <= context_chars * 2:
        return MASKED_TOKEN
    return raw_value[:context_chars] + MASKED_TOKEN + raw_value[-context_chars:]


def build_evidence_line(
    raw_line: str,
    secret_match: Optional[re.Match],
    is_secret_rule: bool,
) -> str:
    """Construct a safe evidence string for a finding.

    For secret rules, the matched group (the actual credential value) is
    replaced with the masked token. For non-secret rules the line is returned
    as-is, stripped of leading/trailing whitespace.

    Args:
        raw_line: The full source line where the pattern matched.
        secret_match: The regex match object (used to locate the secret group).
        is_secret_rule: If True, the captured group is treated as a secret
            and must be masked before output.

    Returns:
        A safe evidence string suitable for inclusion in a Finding.
    """
    stripped = raw_line.strip()
    if not is_secret_rule or secret_match is None:
        return stripped

    try:
        # Group(1) is the captured secret value defined by each secret rule's pattern
        secret_value = secret_match.group(1)
        return stripped.replace(secret_value, MASKED_TOKEN)
    except IndexError:
        # Pattern has no capture group (whole match is the secret, e.g. AKIA key)
        whole_match = secret_match.group(0)
        return stripped.replace(whole_match, MASKED_TOKEN)


def ensure_no_raw_secrets(text: str, known_secrets: list[str]) -> str:
    """Validate that none of the known secret values appear in text.

    If any are found, they are replaced with MASKED_TOKEN. This is a
    last-resort safety net applied before writing user-facing output.

    Args:
        text: The output string to sanitize.
        known_secrets: List of raw secret values to search for.

    Returns:
        The sanitized text with any secrets replaced.
    """
    result = text
    for secret in known_secrets:
        if secret and len(secret) >= 4:
            result = result.replace(secret, MASKED_TOKEN)
    return result
