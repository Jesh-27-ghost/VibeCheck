"""Finding fingerprinting and stable matching logic for rescan comparison.

Provides deterministic fingerprints across file edits where line numbers may shift.
Fingerprints are conservative heuristics to match findings across scans.
"""

import hashlib
import os
import re
from typing import Any, Dict, Optional, Union


def normalize_file_path(path: Optional[str]) -> str:
    """Normalize file paths across operating systems and leading prefixes."""
    if not path:
        return "unknown"
    normalized = path.replace("\\", "/").strip()
    # Strip leading ./ or /
    normalized = re.sub(r"^\.?/+", "", normalized)
    return normalized.lower()


def normalize_evidence(evidence: Any) -> str:
    """Normalize evidence to a stable hashable representation."""
    if isinstance(evidence, dict):
        # Extract meaningful evidence fields
        parts = []
        for key in ["snippet", "excerpt", "pattern", "rule_id", "secret_type"]:
            val = evidence.get(key)
            if val is not None:
                parts.append(f"{key}:{str(val).strip()}")
        if parts:
            text = "|".join(sorted(parts))
        else:
            text = str(evidence)
    elif isinstance(evidence, str):
        text = evidence.strip()
    else:
        text = str(evidence).strip() if evidence is not None else ""

    # Collapse repeated whitespace
    text = re.sub(r"\s+", " ", text)
    return text


def compute_finding_fingerprint(finding: Union[Dict[str, Any], Any]) -> str:
    """Compute a stable hash fingerprint for a finding.

    Based on:
    - rule_id
    - category
    - normalized file path
    - normalized evidence

    Line numbers are intentionally omitted because line shifts occur when code is modified.
    """
    if isinstance(finding, dict):
        rule_id = str(finding.get("rule_id", "")).strip().lower()
        category = str(finding.get("category", "")).strip().lower()
        loc = finding.get("location") or {}
        if isinstance(loc, dict):
            file_path = loc.get("file_path") or loc.get("file") or ""
        else:
            file_path = getattr(loc, "file_path", getattr(loc, "file", ""))
        evidence = finding.get("evidence", "")
    else:
        rule_id = str(getattr(finding, "rule_id", "")).strip().lower()
        category = str(getattr(finding, "category", "")).strip().lower()
        loc = getattr(finding, "location", None)
        if isinstance(loc, dict):
            file_path = loc.get("file_path") or loc.get("file") or ""
        elif loc is not None:
            file_path = getattr(loc, "file_path", getattr(loc, "file", ""))
        else:
            file_path = ""
        evidence = getattr(finding, "evidence", "")

    norm_file = normalize_file_path(file_path)
    norm_evidence = normalize_evidence(evidence)

    raw_signature = f"{rule_id}|{category}|{norm_file}|{norm_evidence}"
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()[:16]
