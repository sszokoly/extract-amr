"""Tests for generated single-file launcher passphrase handling."""

import builtins
import os
from pathlib import Path
import runpy
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILDER = runpy.run_path(str(PROJECT_ROOT / "scripts" / "build_single_file.py"))
PASSPHRASE = "Correct Horse Battery Staple!"


@pytest.fixture(scope="module")
def encrypted_launcher(tmp_path_factory):
    directory = tmp_path_factory.mktemp("encrypted-launcher")
    path = directory / "extract-amr.py"
    source = BUILDER["wrap_launcher"]("print('payload ran')\n", None, PASSPHRASE)
    path.write_text(source, encoding="utf-8")
    namespace = {"__file__": str(path), "__name__": "generated_launcher"}
    exec(compile(source, str(path), "exec"), namespace)
    return namespace, path


@pytest.fixture
def dotenv_path(encrypted_launcher):
    path = encrypted_launcher[1].with_name(".env")
    if path.exists():
        path.unlink()
    yield path
    if path.exists():
        path.unlink()


@pytest.mark.parametrize(
    ("arguments", "expected_passphrase", "expected_arguments"),
    [
        (
            ["bundle", "--enc-passphrase", "secret", "inspect", "capture.pcap"],
            "secret",
            ["bundle", "inspect", "capture.pcap"],
        ),
        (
            ["bundle", "inspect", "capture.pcap", "--enc-passphrase=secret", "--progress"],
            "secret",
            ["bundle", "inspect", "capture.pcap", "--progress"],
        ),
    ],
)
def test_extract_runtime_passphrase_preserves_other_arguments(
    encrypted_launcher,
    arguments,
    expected_passphrase,
    expected_arguments,
) -> None:
    namespace, _ = encrypted_launcher

    passphrase, sanitized = namespace["extract_runtime_passphrase"](arguments)

    assert passphrase == expected_passphrase
    assert sanitized == expected_arguments


def test_extract_runtime_passphrase_stops_at_terminator(encrypted_launcher) -> None:
    namespace, _ = encrypted_launcher
    arguments = ["bundle", "inspect", "--", "--enc-passphrase", "secret"]

    passphrase, sanitized = namespace["extract_runtime_passphrase"](arguments)

    assert passphrase is namespace["_MISSING_PASSPHRASE"]
    assert sanitized == arguments


@pytest.mark.parametrize(
    "arguments",
    [
        ["bundle", "--enc-passphrase"],
        ["bundle", "--enc-passphrase", "--"],
        ["bundle", "--enc-passphrase=one", "--enc-passphrase", "two"],
        ["bundle", "--enc-passphrase", "--enc-passphrase=two"],
    ],
)
def test_extract_runtime_passphrase_rejects_malformed_options(
    encrypted_launcher,
    arguments,
) -> None:
    namespace, _ = encrypted_launcher

    with pytest.raises(ValueError):
        namespace["extract_runtime_passphrase"](arguments)


def test_dotenv_passphrase_comes_from_launcher_directory(
    encrypted_launcher,
    dotenv_path,
    monkeypatch,
) -> None:
    namespace, _ = encrypted_launcher
    dotenv_path.write_text("ENC_PASSPHRASE=from-file\n", encoding="utf-8")
    monkeypatch.setenv("ENC_PASSPHRASE", "from-process")

    assert namespace["read_dotenv_passphrase"]() == "from-file"
    assert os.environ["ENC_PASSPHRASE"] == "from-process"


def test_dotenv_passphrase_does_not_use_working_directory(
    encrypted_launcher,
    dotenv_path,
    tmp_path,
    monkeypatch,
) -> None:
    namespace, _ = encrypted_launcher
    (tmp_path / ".env").write_text("ENC_PASSPHRASE=from-cwd\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert namespace["read_dotenv_passphrase"]() is namespace["_MISSING_PASSPHRASE"]


def test_dotenv_passphrase_is_optional(encrypted_launcher, dotenv_path, monkeypatch) -> None:
    namespace, _ = encrypted_launcher
    original_import = builtins.__import__

    def import_without_dotenv(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("dotenv intentionally unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_dotenv)

    assert namespace["read_dotenv_passphrase"]() is namespace["_MISSING_PASSPHRASE"]


def test_resolve_passphrase_prefers_dotenv_and_sanitizes_argv(
    encrypted_launcher,
    dotenv_path,
    monkeypatch,
) -> None:
    namespace, _ = encrypted_launcher
    dotenv_path.write_text(f"ENC_PASSPHRASE={PASSPHRASE}\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["bundle", "--enc-passphrase", "wrong", "--help"])
    monkeypatch.setattr(
        namespace["getpass"],
        "getpass",
        lambda prompt: pytest.fail(f"unexpected prompt: {prompt}"),
    )

    assert namespace["resolve_passphrase"]() == PASSPHRASE
    assert sys.argv == ["bundle", "--help"]


def test_resolve_passphrase_uses_runtime_option_without_dotenv(
    encrypted_launcher,
    dotenv_path,
    monkeypatch,
) -> None:
    namespace, _ = encrypted_launcher
    monkeypatch.setattr(sys, "argv", ["bundle", "--help", f"--enc-passphrase={PASSPHRASE}"])
    monkeypatch.setattr(
        namespace["getpass"],
        "getpass",
        lambda prompt: pytest.fail(f"unexpected prompt: {prompt}"),
    )

    assert namespace["resolve_passphrase"]() == PASSPHRASE
    assert sys.argv == ["bundle", "--help"]


def test_resolve_passphrase_prompts_as_final_fallback(
    encrypted_launcher,
    dotenv_path,
    monkeypatch,
) -> None:
    namespace, _ = encrypted_launcher
    monkeypatch.setattr(sys, "argv", ["bundle", "--help"])
    monkeypatch.setattr(namespace["getpass"], "getpass", lambda prompt: PASSPHRASE)

    assert namespace["resolve_passphrase"]() == PASSPHRASE


def test_invalid_dotenv_passphrase_does_not_fall_back(
    encrypted_launcher,
    dotenv_path,
    monkeypatch,
    capsys,
) -> None:
    namespace, _ = encrypted_launcher
    dotenv_path.write_text("ENC_PASSPHRASE=wrong\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["bundle", f"--enc-passphrase={PASSPHRASE}"])
    monkeypatch.setattr(
        namespace["getpass"],
        "getpass",
        lambda prompt: pytest.fail(f"unexpected prompt: {prompt}"),
    )

    with pytest.raises(SystemExit, match="1"):
        namespace["decrypt_script"](namespace["COMPRESSED_SCRIPT"])

    assert capsys.readouterr().err == "error: decryption failed\n"


def test_valueless_dotenv_passphrase_is_rejected_by_resolver(
    encrypted_launcher,
    dotenv_path,
    monkeypatch,
) -> None:
    namespace, _ = encrypted_launcher
    dotenv_path.write_text("ENC_PASSPHRASE\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["bundle", f"--enc-passphrase={PASSPHRASE}"])
    monkeypatch.setattr(
        namespace["getpass"],
        "getpass",
        lambda prompt: pytest.fail(f"unexpected prompt: {prompt}"),
    )

    with pytest.raises(ValueError, match="invalid passphrase"):
        namespace["resolve_passphrase"]()


def test_missing_cryptography_precedes_passphrase_resolution(
    encrypted_launcher,
    dotenv_path,
    monkeypatch,
    capsys,
) -> None:
    namespace, _ = encrypted_launcher
    original_import = builtins.__import__
    arguments = ["bundle", "--enc-passphrase"]
    monkeypatch.setattr(sys, "argv", arguments.copy())

    def import_without_cryptography(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("cryptography intentionally unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_cryptography)

    with pytest.raises(SystemExit, match="1"):
        namespace["decrypt_script"](namespace["COMPRESSED_SCRIPT"])

    assert sys.argv == arguments
    assert capsys.readouterr().err == "error: encrypted bundle requires Cryptography\n"


def test_unencrypted_launcher_has_no_passphrase_resolution() -> None:
    source = BUILDER["wrap_launcher"]("print('payload ran')\n", None)

    assert "dotenv" not in source
    assert "ENC_PASSPHRASE" not in source
    assert "--enc-passphrase" not in source
    assert "getpass" not in source
    assert "KDF_" not in source
    assert "cryptography" not in source
