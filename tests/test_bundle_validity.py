"""Tests for generated bundle expiration enforcement."""

from typing import Any

from click.testing import CliRunner
import pytest

import extract_amr.bundle_validity as bundle_validity
from extract_amr.cli import cli


@pytest.mark.parametrize("validity", [101, 101.0])
def test_bundle_validity_accepts_future_values(monkeypatch, validity: Any) -> None:
    monkeypatch.setattr(bundle_validity.time, "time", lambda: 100.0)

    bundle_validity._enforce_bundle_validity(validity)


def test_bundle_validity_accepts_current_epoch(monkeypatch) -> None:
    monkeypatch.setattr(bundle_validity.time, "time", lambda: 100.0)

    bundle_validity._enforce_bundle_validity(100.0)


def test_bundle_validity_rejects_expired_value(monkeypatch, capsys) -> None:
    monkeypatch.setattr(bundle_validity.time, "time", lambda: 100.0)

    with pytest.raises(SystemExit, match="1"):
        bundle_validity._enforce_bundle_validity(99.0)

    assert capsys.readouterr().err == "error: this extract-amr bundle has expired\n"


@pytest.mark.parametrize("validity", [True, "100", None, float("inf"), float("nan")])
def test_bundle_validity_rejects_invalid_value(capsys, validity: Any) -> None:
    with pytest.raises(SystemExit, match="1"):
        bundle_validity._enforce_bundle_validity(validity)

    assert capsys.readouterr().err == "error: invalid bundle validity metadata\n"


def test_normal_cli_use_does_not_enforce_bundle_validity(monkeypatch) -> None:
    def unexpected_enforcement(validity: Any) -> None:
        raise AssertionError(f"unexpected bundle validity enforcement: {validity}")

    monkeypatch.setattr(bundle_validity, "_enforce_bundle_validity", unexpected_enforcement)

    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
