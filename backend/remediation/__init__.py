"""Consolidated remediation prompt generator module for VibeShield."""

from backend.remediation.prompt import generate_repair_prompt  # noqa: F401


class RemediationService:
    """Thin service wrapper around generate_repair_prompt for checkpoint detection."""

    def build_prompt(self, scan_id: str, project_name: str, findings: list, **kwargs) -> str:
        return generate_repair_prompt(scan_id, project_name, findings, **kwargs)


__all__ = ["generate_repair_prompt", "RemediationService"]
