"""pytest conftest.py — shared fixtures for the VibeShield test suite.

Overrides the tmp_path fixture to stay within the workspace root so that
the sandbox can write test artifacts without hitting OS temp dir restrictions.
Each test gets its own unique directory; no cleanup is attempted between runs
since the sandbox blocks os.rmdir on certain paths.
"""

import uuid
from pathlib import Path

import pytest

# Place all test temp dirs inside the workspace to avoid sandbox restrictions on %TEMP%
_WORKSPACE_ROOT = Path(__file__).parent.parent.parent
_TEST_TMP_BASE = _WORKSPACE_ROOT / "temp_scans" / "test_tmp"
_TEST_TMP_BASE.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def tmp_path() -> Path:
    """Override pytest's tmp_path to use a directory inside the workspace.

    This avoids sandbox PermissionError when pytest tries to clean up
    system temp directories between test runs on Windows.
    Each call returns a fresh unique directory within temp_scans/test_tmp/.
    """
    unique_dir = _TEST_TMP_BASE / f"t_{uuid.uuid4().hex[:12]}"
    unique_dir.mkdir(parents=True, exist_ok=True)
    return unique_dir
