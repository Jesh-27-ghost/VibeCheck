"""Deterministic security rule definitions for VibeShield.

Each rule is a compiled pattern that matches common vulnerability patterns
in web application source code. Rules do NOT execute submitted code.
All secret-like values are masked before any finding leaves the scanner.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Rule:
    """Single deterministic security rule."""

    rule_id: str
    category: str
    title: str
    severity: str          # critical | high | medium | low | info
    confidence: str        # high | medium | low
    pattern: re.Pattern
    impact: str
    recommendation: str
    verification_steps: tuple = field(default_factory=tuple)
    is_secret_rule: bool = False  # True → mask matched value before output


# ---------------------------------------------------------------------------
# Secret / credential detection patterns
# ---------------------------------------------------------------------------

_SECRET_RULES: list[Rule] = [
    Rule(
        rule_id="SECRET_001",
        category="exposed_secret",
        title="Hardcoded API Key / Token",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:api[_\-\.]?key|api[_\-\.]?token|access[_\-\.]?token|auth[_\-\.]?token)\s*[=:]\s*['"]([^'"]{8,})['"]""",
            re.MULTILINE,
        ),
        impact=(
            "A hardcoded API key or token in source code may be extracted by anyone "
            "with access to the repository or deployed bundle, potentially granting "
            "unauthorized access to the associated service."
        ),
        recommendation=(
            "Remove the hardcoded key. Load secrets exclusively from environment "
            "variables (e.g., os.environ['API_KEY']) or a secrets manager. "
            "Rotate/revoke the exposed key with its provider immediately if it was live."
        ),
        verification_steps=(
            "Revoke or rotate the exposed key with its provider.",
            "Search the entire repository (including git history) for remaining copies.",
            "Move the value to an environment variable or secrets manager.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=True,
    ),
    Rule(
        rule_id="SECRET_002",
        category="exposed_secret",
        title="Hardcoded Password Assignment",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"]""",
            re.MULTILINE,
        ),
        impact=(
            "A hardcoded password embedded in source code may be extracted from "
            "version control or deployed artifacts, enabling unauthorized authentication."
        ),
        recommendation=(
            "Replace the hardcoded password with an environment variable or secrets "
            "manager reference. Rotate the credential immediately if it was live."
        ),
        verification_steps=(
            "Change or revoke the password with the relevant service.",
            "Replace the assignment with os.environ['PASSWORD'] or equivalent.",
            "Verify git history and other branches do not still contain the value.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=True,
    ),
    Rule(
        rule_id="SECRET_003",
        category="exposed_secret",
        title="Hardcoded Private Key or Certificate Material",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----""",
            re.MULTILINE,
        ),
        impact=(
            "An embedded private key allows an attacker to impersonate the server, "
            "decrypt TLS traffic, or sign arbitrary data with the compromised key pair."
        ),
        recommendation=(
            "Remove the private key from source immediately. Store keys in a secrets "
            "manager or hardware security module. Revoke and reissue the certificate pair."
        ),
        verification_steps=(
            "Revoke the certificate and private key with the issuing CA.",
            "Remove all copies from the repository and its history.",
            "Provision a new key pair securely and store it outside version control.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=True,
    ),
    Rule(
        rule_id="SECRET_004",
        category="exposed_secret",
        title="Hardcoded Secret or Connection String",
        severity="high",
        confidence="low",
        pattern=re.compile(
            r"""(?i)(?:secret|database_url|connection_string|db_url|db_password|mongo_uri|redis_url|jwt_secret)\s*[=:]\s*['"]([^'"]{6,})['"]""",
            re.MULTILINE,
        ),
        impact=(
            "A hardcoded connection string or generic secret can expose database "
            "credentials, service endpoints, or signing keys to unauthorized parties."
        ),
        recommendation=(
            "Load this value from an environment variable or secrets manager. "
            "Rotate the secret immediately if it was a live credential."
        ),
        verification_steps=(
            "Identify whether the value is a live credential and rotate it if so.",
            "Replace with an environment variable reference.",
            "Review git history for other occurrences.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=True,
    ),
    Rule(
        rule_id="SECRET_005",
        category="exposed_secret",
        title="AWS Access Key ID Pattern",
        severity="critical",
        confidence="high",
        pattern=re.compile(
            r"""(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])""",
            re.MULTILINE,
        ),
        impact=(
            "An AWS Access Key ID matching the AKIA… pattern is likely a live IAM "
            "credential that could grant an attacker access to AWS resources."
        ),
        recommendation=(
            "Immediately deactivate and delete this IAM access key in the AWS console. "
            "Review CloudTrail logs for unauthorized use. Issue a new key and store it "
            "in AWS Secrets Manager or as an environment variable."
        ),
        verification_steps=(
            "Deactivate the key in IAM immediately.",
            "Review CloudTrail for unauthorized API calls.",
            "Generate a replacement key and store securely.",
            "Search git history for further occurrences.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=True,
    ),
]

# ---------------------------------------------------------------------------
# Static analysis rules (insecure configuration patterns)
# ---------------------------------------------------------------------------

_STATIC_RULES: list[Rule] = [
    Rule(
        rule_id="CORS_001",
        category="insecure_configuration",
        title="Wildcard CORS Policy Detected",
        severity="medium",
        confidence="high",
        pattern=re.compile(
            r"""(?i)(?:access.control.allow.origin|cors\s*\(|allow_origins\s*=)\s*['"*\[\s]*\*""",
            re.MULTILINE,
        ),
        impact=(
            "A wildcard CORS policy allows any external origin to make credentialed "
            "cross-origin requests, potentially facilitating CSRF or data exfiltration."
        ),
        recommendation=(
            "Replace the wildcard with an explicit allowlist of trusted origins. "
            "Example: allow_origins=['https://yourdomain.com']"
        ),
        verification_steps=(
            "Identify all legitimate client origins.",
            "Replace * with an explicit allowlist.",
            "Test that unauthorized origins are rejected.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=False,
    ),
    Rule(
        rule_id="DEBUG_001",
        category="insecure_configuration",
        title="Debug Mode Enabled in Production Config",
        severity="medium",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)""",
            re.MULTILINE,
        ),
        impact=(
            "Debug mode exposes detailed stack traces and internal state to end users, "
            "which can leak sensitive path information and application internals."
        ),
        recommendation=(
            "Set debug=False in production. Control debug mode through an environment "
            "variable: DEBUG=os.getenv('DEBUG', 'false').lower() == 'true'"
        ),
        verification_steps=(
            "Replace the hardcoded True with an environment variable check.",
            "Verify the application starts without exposing debug endpoints.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=False,
    ),
    Rule(
        rule_id="SQL_001",
        category="injection",
        title="Possible SQL Injection via String Formatting",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""(?i)(?:execute|cursor\.execute|query)\s*\(\s*(?:f['"]|['"].*%s|['"].*\+\s*\w)""",
            re.MULTILINE,
        ),
        impact=(
            "Constructing SQL queries by string formatting or concatenation with "
            "user-supplied data may allow SQL injection, enabling data exfiltration, "
            "modification, or deletion."
        ),
        recommendation=(
            "Use parameterized queries or prepared statements. Pass user input as "
            "query parameters, never concatenate or format it into the SQL string."
        ),
        verification_steps=(
            "Locate all database query call sites.",
            "Replace f-strings and concatenation with parameterized placeholders.",
            "Test with payloads like '; DROP TABLE users; --.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=False,
    ),
    Rule(
        rule_id="EVAL_001",
        category="injection",
        title="Use of eval() with Potentially Untrusted Input",
        severity="high",
        confidence="medium",
        pattern=re.compile(
            r"""\beval\s*\(\s*(?:request|input|data|params|body|query|user)""",
            re.MULTILINE,
        ),
        impact=(
            "Passing user-controlled data to eval() allows arbitrary code execution "
            "in the server process, giving an attacker full control of the host."
        ),
        recommendation=(
            "Never use eval() with external input. Parse structured data with safe "
            "deserializers (json.loads, ast.literal_eval for known types) instead."
        ),
        verification_steps=(
            "Replace eval() with a safe alternative (json.loads, ast.literal_eval).",
            "Validate and sanitize input before any processing.",
            "Rerun VibeCheck on the corrected source.",
        ),
        is_secret_rule=False,
    ),
    Rule(
        rule_id="NOSEC_001",
        category="insecure_configuration",
        title="Security Control Suppression Comment (# nosec)",
        severity="info",
        confidence="high",
        pattern=re.compile(
            r"""#\s*nosec\b""",
            re.MULTILINE,
        ),
        impact=(
            "The # nosec comment suppresses automated security warnings. "
            "This may hide genuine vulnerabilities if applied without justification."
        ),
        recommendation=(
            "Review each # nosec annotation and confirm it has a documented rationale. "
            "Remove the annotation unless the suppression is intentional and safe."
        ),
        verification_steps=(
            "Locate every # nosec comment in the codebase.",
            "Confirm or document the rationale for each suppression.",
            "Remove unjustified suppressions.",
        ),
        is_secret_rule=False,
    ),
]

# Public list of all rules (secret rules first so they appear prominently)
ALL_RULES: list[Rule] = _SECRET_RULES + _STATIC_RULES
