"""Security scanning engine package for VibeShield.

Exports the deterministic rule-based scanner used in Phase 3+.
"""

from backend.scanners.engine import ScannerEngine, run_scanners  # noqa: F401
from backend.scanners.rules import ALL_RULES as RuleRegistry  # noqa: F401

__all__ = ["ScannerEngine", "run_scanners", "RuleRegistry"]
