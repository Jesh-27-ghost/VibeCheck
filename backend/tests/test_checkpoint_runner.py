"""Automated unit tests for the Phase Checkpoint runner and All-Phase Dashboard system."""

import io
import sys
from pathlib import Path

from scripts.checkpoints import PHASE_REGISTRY
from scripts.checkpoints.common import CheckStatus, REPO_ROOT
from scripts.checkpoints.phase1 import Phase1Check
from scripts.checkpoints.phase2 import Phase2Check
from scripts.checkpoints.phase3 import Phase3Check
from scripts.checkpoints.phase4 import Phase4Check
from scripts.checkpoints.phase5 import Phase5Check


def _run_phase_check_inprocess(args: list[str]) -> tuple[int, str, str]:
    """Run phase_check.py logic in-process and return (returncode, stdout, stderr).

    The sandbox blocks subprocess spawning with piped I/O (DuplicateHandle for
    the invalid console handles fails). We import the script's main() instead.
    """
    import importlib.util
    import importlib

    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    saved_argv = sys.argv
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr
    exit_code = 0

    try:
        sys.argv = ["phase_check.py"] + args
        sys.stdout = stdout_buf
        sys.stderr = stderr_buf

        # Load and execute the script module in-process
        spec = importlib.util.spec_from_file_location("phase_check", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        try:
            exit_code = module.main()
        except SystemExit as e:
            exit_code = int(e.code) if e.code is not None else 0
    finally:
        sys.argv = saved_argv
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr

    return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()


def test_phase_registry_contains_all_seven_phases():
    """Verify that phases 1 through 7 are registered."""
    assert set(PHASE_REGISTRY.keys()) == {1, 2, 3, 4, 5, 6, 7}


def test_phase_1_checks_pass():
    """Verify that Phase 1 programmatic execution passes completely."""
    results = Phase1Check.run_all()
    assert len(results) >= 6
    for result in results:
        assert (
            result.status == CheckStatus.PASS
        ), f"Phase 1 check failed: {result.name} - {result.details}"


def test_phase_2_checks_pass():
    """Verify that Phase 2 programmatic execution passes completely now that intake is built."""
    results = Phase2Check.run_all()
    assert len(results) == 10
    for result in results:
        assert (
            result.status == CheckStatus.PASS
        ), f"Phase 2 check failed: {result.name} - {result.details}"


def test_phase_3_scanner_module_is_implemented():
    """Verify that Phase 3 scanner module is now implemented and detected."""
    results = Phase3Check.run_all()
    assert len(results) > 0
    not_impl = [r for r in results if r.status == CheckStatus.NOT_IMPLEMENTED]
    assert len(not_impl) < len(results), (
        "All Phase 3 checks still report NOT_IMPLEMENTED — scanner integration missing"
    )


def test_phase_4_remediation_is_implemented():
    """Verify that Phase 4 remediation module is detected and passing."""
    results = Phase4Check.run_all()
    assert len(results) > 0
    not_impl = [r for r in results if r.status == CheckStatus.NOT_IMPLEMENTED]
    assert len(not_impl) < len(results), (
        "All Phase 4 checks still report NOT_IMPLEMENTED — remediation module missing"
    )


def test_phase_check_cli_phase_1_passes():
    """Run phase_check logic for phase 1 in-process and assert it passes."""
    rc, stdout, stderr = _run_phase_check_inprocess(["1"])
    assert rc == 0, f"Expected 0, got {rc}:\nstdout: {stdout}\nstderr: {stderr}"
    assert "Result: PASSED" in stdout
    assert "Foundation & Contracts" in stdout


def test_phase_check_cli_phase_2_passes():
    """Run phase_check logic for phase 2 in-process and assert it passes."""
    rc, stdout, stderr = _run_phase_check_inprocess(["2"])
    assert rc == 0, f"Expected 0, got {rc}:\nstdout: {stdout}\nstderr: {stderr}"
    assert "Result: PASSED" in stdout
    assert "Secure Source Code Intake" in stdout


def test_phase_check_cli_phase_3_passes():
    """Run phase_check logic for phase 3 in-process and assert it passes."""
    rc, stdout, stderr = _run_phase_check_inprocess(["3"])
    assert rc == 0, (
        f"Expected Phase 3 to pass (exit 0) after implementation, "
        f"got {rc}.\nstdout: {stdout}\nstderr: {stderr}"
    )
    assert "Result: PASSED" in stdout
    assert "Security Scanner Integration" in stdout


def test_phase_5_comparison_is_implemented():
    """Verify that Phase 5 comparison module is detected and passing."""
    results = Phase5Check.run_all()
    assert len(results) == 7
    for r in results:
        assert r.status == CheckStatus.PASS, f"Phase 5 check failed: {r.name} - {r.details}"


def test_phase_check_cli_phase_5_passes():
    """Run phase_check logic for phase 5 in-process and assert it passes."""
    rc, stdout, stderr = _run_phase_check_inprocess(["5"])
    assert rc == 0, (
        f"Expected Phase 5 to pass (exit 0) after implementation, "
        f"got {rc}.\nstdout: {stdout}\nstderr: {stderr}"
    )
    assert "Result: PASSED" in stdout
    assert "Rescan Comparison & Verification" in stdout


def test_phase_check_cli_dashboard_no_args():
    """Run phase_check with no args in-process and assert dashboard output."""
    rc, stdout, stderr = _run_phase_check_inprocess([])
    # Exits 0 because all 7 phases are passing
    assert rc == 0
    assert "VibeShield All-Phase Status Dashboard" in stdout
    assert "Phase 1: Foundation & Contracts" in stdout
    assert "Phase 2: Secure Source Code Intake" in stdout
    assert "Phase 3: Security Scanner Integration" in stdout
    assert "Progress:" in stdout


def test_phase_check_cli_dashboard_all_flag():
    """Run phase_check --all in-process and assert dashboard output."""
    rc, stdout, stderr = _run_phase_check_inprocess(["--all"])
    assert rc == 0
    assert "VibeShield All-Phase Status Dashboard" in stdout
    assert "Progress:" in stdout


def test_phase_check_cli_invalid_phase_number():
    """Verify passing an out-of-range phase number returns exit code 2."""
    rc, stdout, stderr = _run_phase_check_inprocess(["99"])
    assert rc == 2
    assert "Invalid phase number '99'" in stderr


def test_phase_check_cli_non_integer_argument():
    """Verify passing a non-integer argument returns exit code 2."""
    rc, stdout, stderr = _run_phase_check_inprocess(["invalid"])
    assert rc == 2
    assert "Phase argument must be an integer (1-7)" in stderr
