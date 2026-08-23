"""Parity and fallback tests for local bit-processing backends."""

import importlib
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from extract_amr import bits


def _missing_importer(name: str):
    raise ModuleNotFoundError(f"No module named '{name}'")


def _python_backend():
    return bits._select_backend(_missing_importer)


def _accelerated_backend():
    pytest.importorskip("bitarray")
    backend = bits._select_backend(importlib.import_module)
    assert backend.name == "bitarray"
    return backend


@pytest.mark.parametrize(
    "backend_factory",
    [_python_backend, _accelerated_backend],
    ids=["python", "bitarray"],
)
def test_backend_implements_the_local_bit_contract(backend_factory) -> None:
    backend = backend_factory()
    value = backend.from_bytes(b"\xb2\x60", bit_length=11)

    assert len(value) == 11
    assert value.to01() == "10110010011"
    assert list(value) == [1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1]
    assert value[0] == 1
    assert value[-1] == 1
    assert value[1:9].to01() == "01100100"
    assert value.to_bytes() == b"\xb2\x60"

    suffix = backend.from_iterable([0, 1, True, False])
    combined = value[2:6] + suffix
    assert combined.to01() == "11000110"
    assert combined.to_bytes() == b"\xc6"


@pytest.mark.parametrize(
    "backend_factory",
    [_python_backend, _accelerated_backend],
    ids=["python", "bitarray"],
)
def test_backend_validation_is_consistent(backend_factory) -> None:
    backend = backend_factory()
    value = backend.from_iterable([1, 0, 1])

    with pytest.raises(IndexError, match="out of range"):
        _ = value[3]
    with pytest.raises(ValueError, match="step of 1"):
        _ = value[::2]
    with pytest.raises(ValueError, match="available bits"):
        backend.from_bytes(b"\x00", bit_length=9)
    with pytest.raises(ValueError, match="only 0 or 1"):
        backend.from_iterable([0, 2])


def test_public_aliases_use_the_selected_backend() -> None:
    left = bits.bits_from_bytes(b"\xa0", bit_length=4)
    right = bits.bits_from_iterable([0, 1, 1])
    combined = bits.concat_bits(left, right)

    assert isinstance(left, bits.BitBuffer)
    assert combined.to01() == "1010011"
    assert bits.bits_to_bytes(combined) == b"\xa6"
    assert bits.BIT_BACKEND.name in {"python", "bitarray"}


def test_missing_dependency_selects_python_with_reason() -> None:
    backend = bits._select_backend(_missing_importer)

    assert backend.name == "python"
    assert backend.buffer_type is bits._PythonBitBuffer
    assert backend.fallback_reason is not None
    assert backend.fallback_reason.startswith("ModuleNotFoundError:")


def test_initialization_exception_selects_python_with_sanitized_reason() -> None:
    class BrokenBitarray:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            raise RuntimeError("native\ninitialization failed")

    backend = bits._select_backend(
        lambda name: SimpleNamespace(bitarray=BrokenBitarray),
    )

    assert backend.name == "python"
    assert backend.fallback_reason == "RuntimeError: native initialization failed"


def test_backend_selection_does_not_catch_base_exception() -> None:
    def interrupt(name: str):
        del name
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        bits._select_backend(interrupt)


def test_package_imports_when_bitarray_is_unavailable(tmp_path: Path) -> None:
    blocker = tmp_path / "bitarray.py"
    blocker.write_text(
        "raise ModuleNotFoundError(\"No module named 'bitarray'\")\n",
        encoding="ascii",
    )
    project_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(tmp_path), str(project_root)],
    )

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import extract_amr; "
                "print(extract_amr.BIT_BACKEND.name); "
                "print(extract_amr.BIT_BACKEND.fallback_reason)"
            ),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == "python"
    assert lines[1].startswith("ModuleNotFoundError:")
