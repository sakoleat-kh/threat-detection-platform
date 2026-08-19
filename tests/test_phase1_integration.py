"""End-to-end integration tests for Phase 1 log parsers."""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

def run_cli(module: str, log_file: str) -> subprocess.CompletedProcess[str]:
    """Run a CLI module against a sample log file."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            module,
            str(PROJECT_ROOT / log_file),
        ],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        check=False,
    )

def test_auth_cli_processes_full_sample():
    result = run_cli(
        "app.parsers.cli_auth_reader",
        "data/sample_logs/auth_sample.log",
    )

    assert result.returncode == 0
    assert "Event Summary" in result.stdout
    assert "unknown" in result.stdout
    assert "sudo_command" in result.stdout

def test_access_cli_processes_full_sample():
    result = run_cli(
        "app.parsers.cli_access_reader",
        "data/sample_logs/access_sample.log",
    )

    assert result.returncode == 0
    assert "HTTP Status Summary" in result.stdout
    assert "200" in result.stdout
    assert "404" in result.stdout