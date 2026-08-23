"""Validate the recorded isolated base-install verification."""

import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def _source_sha256() -> str:
    digest = hashlib.sha256()
    paths = sorted((PROJECT_ROOT / "extract_amr").glob("*.py"))
    paths.extend(
        (
            PROJECT_ROOT / "pyproject.toml",
            PROJECT_ROOT / "tests" / "fixtures" / "directional_modes.pcap",
            PROJECT_ROOT / "scripts" / "verify_base_install.py",
        ),
    )
    for path in paths:
        digest.update(str(path.relative_to(PROJECT_ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def test_recorded_base_install_uses_no_bitarray_and_extracts_golden() -> None:
    result_path = PROJECT_ROOT / "verification" / "base-install-python3.8.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))

    assert result["python"].startswith("Python 3.8.")
    assert result["backend"]["backend"] == "python"
    assert result["backend"]["bitarray_present"] is False
    assert result["backend"]["fallback_reason"]
    assert result["output_sha256"] == result["expected_sha256"]
    assert result["cli_reported_python_backend"] is True
    assert result["source_sha256"] == _source_sha256()
    assert result["passed"] is True
