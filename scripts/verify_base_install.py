"""Verify the built project in an isolated environment without bitarray."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "directional_modes.pcap"
EXPECTED_SHA256 = "d273d9e15f8df03e26ab8de4fb90d4328adaf393ea244e6b9204c946d604bde4"


def _source_sha256() -> str:
    digest = hashlib.sha256()
    paths = sorted((PROJECT_ROOT / "extract_amr").glob("*.py"))
    paths.extend((PROJECT_ROOT / "pyproject.toml", FIXTURE, Path(__file__).resolve()))
    for path in paths:
        digest.update(str(path.relative_to(PROJECT_ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _run(command, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(item) for item in command],
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
        **kwargs,
    )


def verify() -> dict:
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required for isolated installation verification")
    with tempfile.TemporaryDirectory(prefix="extract-amr-base-install-") as temporary:
        root = Path(temporary)
        environment = root / "environment"
        _run((uv, "venv", "--python", "3.8", environment))
        binary_dir = environment / ("Scripts" if os.name == "nt" else "bin")
        python = binary_dir / "python"
        command = binary_dir / "extract-amr"
        _run((uv, "pip", "install", "--python", python, PROJECT_ROOT))
        probe = _run(
            (
                python,
                "-c",
                "import importlib.util, json, extract_amr; "
                "print(json.dumps({'backend': extract_amr.BIT_BACKEND.name, "
                "'fallback_reason': extract_amr.BIT_BACKEND.fallback_reason, "
                "'bitarray_present': importlib.util.find_spec('bitarray') is not None}))",
            ),
            cwd=str(root),
        )
        backend = json.loads(probe.stdout)
        if backend["bitarray_present"] or backend["backend"] != "python":
            raise RuntimeError("base installation did not select the pure-Python backend")

        output = root / "fixture.amr"
        extraction = _run(
            (
                command,
                "extract",
                FIXTURE,
                "--output",
                output,
                "--src-address",
                "192.0.2.1",
                "--dst-address",
                "192.0.2.2",
                "--src-port",
                "4000",
                "--dst-port",
                "5000",
                "--ssrc",
                str(0x11111111),
                "--payload-type",
                "96",
                "--codec",
                "amr",
                "--mode",
                "octet-aligned",
            ),
            cwd=str(root),
        )
        output_sha256 = hashlib.sha256(output.read_bytes()).hexdigest()
        if output_sha256 != EXPECTED_SHA256:
            raise RuntimeError("base installation extraction did not match the golden output")
        if "bit-backend: python" not in extraction.stdout:
            raise RuntimeError("CLI report did not identify the pure-Python backend")
        return {
            "python": _run((python, "--version")).stdout.strip(),
            "backend": backend,
            "output_sha256": output_sha256,
            "expected_sha256": EXPECTED_SHA256,
            "cli_reported_python_backend": True,
            "source_sha256": _source_sha256(),
            "passed": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = verify()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
