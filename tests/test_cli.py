"""Tests for the Milestone 1 command-line contract."""

import gzip
import os
import struct
from pathlib import Path
from typing import List

import extract_amr.cli as cli_module
import click._termui_impl as click_termui
from click.testing import CliRunner
import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, PcapWriter

from extract_amr import __version__
from extract_amr.cli import cli
from extract_amr.models import (
    Codec,
    ExtractOptions,
    FlowKey,
    GapPolicy,
    InspectOptions,
    PayloadMode,
    ResourceLimits,
    SelectedFlow,
)


def _capture(tmp_path: Path) -> Path:
    capture = tmp_path / "call.pcapng"
    capture.write_bytes(b"placeholder")
    return capture


def _speech_data(bit_count: int, fill: int = 0) -> bytes:
    byte_count = (bit_count + 7) // 8
    data = bytearray([fill] * byte_count)
    padding = byte_count * 8 - bit_count
    if padding:
        data[-1] &= 0xFF << padding
    return bytes(data)


def _amr_payload(*, fill: int = 0, quality: bool = True) -> bytes:
    frame_type = 1
    toc = (frame_type << 3) | (int(quality) << 2)
    return bytes([0xF0, toc]) + _speech_data(103, fill)


def _storage_frame(*, fill: int = 0, quality: bool = True) -> bytes:
    return bytes([(1 << 3) | (int(quality) << 2)]) + _speech_data(103, fill)


def _rtp(
    payload: bytes,
    *,
    sequence: int,
    timestamp: int,
    ssrc: int = 1,
) -> bytes:
    return struct.pack("!BBHII", 0x80, 96, sequence, timestamp, ssrc) + payload


def _packet(payload: bytes):
    return (
        Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=4000, dport=5000) / Raw(payload)
    )


def _write_capture(path: Path, packets) -> None:
    if path.suffix == ".pcapng":
        writer = PcapNgWriter(str(path))
    else:
        writer = PcapWriter(str(path), linktype=1, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def _flow(ssrc: int) -> FlowKey:
    return FlowKey("192.0.2.1", "192.0.2.2", 4000, 5000, ssrc, 96)


def _selection(ssrc: int) -> SelectedFlow:
    return SelectedFlow(
        candidate_id=f"flow-{ssrc}",
        flow_key=_flow(ssrc),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
        first_packet_number=1,
    )


def _explicit_arguments() -> List[str]:
    return [
        "--src-address",
        "192.0.2.1",
        "--dst-address",
        "192.0.2.2",
        "--src-port",
        "4000",
        "--dst-port",
        "5000",
        "--ssrc",
        "1",
        "--payload-type",
        "96",
        "--codec",
        "amr",
        "--mode",
        "octet-aligned",
    ]


def test_top_level_and_command_help() -> None:
    runner = CliRunner()

    result = runner.invoke(cli, ["--help"])
    inspect_help = runner.invoke(cli, ["inspect", "--help"])
    extract_help = runner.invoke(cli, ["extract", "--help"])

    assert result.exit_code == 0
    assert "inspect" in result.output
    assert "extract" in result.output
    assert "--version" in result.output
    assert "--src-port" in inspect_help.output
    assert "--output-dir" in extract_help.output
    assert "--gap-policy" in extract_help.output
    assert "--progress" in inspect_help.output
    assert "--progress" in extract_help.output


def test_version_option() -> None:
    result = CliRunner().invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert result.output.endswith(f", version {__version__}\n")


def test_extract_converts_a_complete_flow_to_typed_options(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = _capture(tmp_path)
    output = tmp_path / "call.awb"
    runner = CliRunner()
    received: List[ExtractOptions] = []
    monkeypatch.setattr(cli_module, "_run_extract", received.append)

    result = runner.invoke(
        cli,
        [
            "extract",
            str(capture),
            "--src-address",
            "192.0.2.1",
            "--dst-address",
            "192.0.2.2",
            "--src-port",
            "4000",
            "--dst-port",
            "5000",
            "--ssrc",
            "42",
            "--payload-type",
            "96",
            "--codec",
            "amr-wb",
            "--mode",
            "octet-aligned",
            "--gap-policy",
            "no-data",
            "--malformed-policy",
            "strict",
            "--reorder-window",
            "32",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert len(received) == 1
    options = received[0]
    assert options.codec is Codec.AMR_WB
    assert options.payload_mode is PayloadMode.OCTET_ALIGNED
    assert options.gap_policy is GapPolicy.NO_DATA
    assert options.limits.reorder_window == 32
    assert options.selector.is_complete
    assert options.output_path == output


def test_port_filter_requires_output_directory(tmp_path: Path, monkeypatch) -> None:
    capture = _capture(tmp_path)
    runner = CliRunner()
    received: List[ExtractOptions] = []
    monkeypatch.setattr(cli_module, "_run_extract", received.append)

    invalid = runner.invoke(
        cli,
        ["extract", str(capture), "--src-port", "4000", "--output", "call.amr"],
    )
    valid = runner.invoke(
        cli,
        [
            "extract",
            str(capture),
            "--src-port",
            "4000",
            "--output-dir",
            str(tmp_path / "outputs"),
        ],
    )

    assert invalid.exit_code == 2
    assert "requires output_dir" in invalid.output
    assert valid.exit_code == 0
    assert len(received) == 1
    assert received[0].selector.is_port_filter


def test_output_options_are_mutually_exclusive_and_required(tmp_path: Path) -> None:
    capture = _capture(tmp_path)
    runner = CliRunner()

    missing = runner.invoke(cli, ["extract", str(capture)])
    conflicting = runner.invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            "call.amr",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert missing.exit_code == 2
    assert conflicting.exit_code == 2
    assert "exactly one" in missing.output
    assert "exactly one" in conflicting.output


def test_click_rejects_invalid_ports_codec_and_mode(tmp_path: Path) -> None:
    capture = _capture(tmp_path)
    runner = CliRunner()

    invalid_port = runner.invoke(
        cli,
        ["inspect", str(capture), "--src-port", "70000"],
    )
    invalid_codec = runner.invoke(
        cli,
        ["inspect", str(capture), "--codec", "evs"],
    )
    invalid_mode = runner.invoke(
        cli,
        ["inspect", str(capture), "--mode", "iu"],
    )

    assert invalid_port.exit_code == 2
    assert invalid_codec.exit_code == 2
    assert invalid_mode.exit_code == 2


def test_inspect_converts_resource_and_selector_options(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = _capture(tmp_path)
    runner = CliRunner()
    received: List[InspectOptions] = []
    monkeypatch.setattr(cli_module, "_run_inspect", received.append)

    result = runner.invoke(
        cli,
        [
            "inspect",
            str(capture),
            "--dst-port",
            "5000",
            "--codec",
            "amr",
            "--mode",
            "bandwidth-efficient",
            "--max-candidates",
            "12",
            "--max-samples-per-flow",
            "8",
            "--max-diagnostics",
            "4",
        ],
    )

    assert result.exit_code == 0
    assert len(received) == 1
    options = received[0]
    assert options.codec is Codec.AMR
    assert options.payload_mode is PayloadMode.BANDWIDTH_EFFICIENT
    assert options.selector.dst_port == 5000
    assert options.limits.max_candidates == 12
    assert options.limits.max_samples_per_flow == 8
    assert options.limits.max_diagnostics == 4


def test_inspect_renders_deterministic_candidate_selector(tmp_path: Path) -> None:
    capture = tmp_path / "inspect.pcap"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )

    result = CliRunner().invoke(cli, ["inspect", str(capture), "--codec", "amr"])

    assert result.exit_code == 0
    assert "capture: packets=1 udp=1 rtp=1 malformed-rtp=0" in result.output
    assert "candidate: flow-" in result.output
    assert "--src-address 192.0.2.1 --dst-address 192.0.2.2" in result.output
    assert "--src-port 4000 --dst-port 5000 --ssrc 1 --payload-type 96" in result.output
    assert "formats: amr/octet-aligned samples=1" in result.output
    assert "bit-backend:" in result.output


def test_automatic_and_explicit_cli_extraction(tmp_path: Path) -> None:
    capture = tmp_path / "extract.pcap"
    automatic_output = tmp_path / "automatic.amr"
    explicit_output = tmp_path / "explicit.amr"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(fill=0x11), sequence=1, timestamp=0))],
    )
    runner = CliRunner()

    automatic = runner.invoke(
        cli,
        ["extract", str(capture), "--output", str(automatic_output)],
    )
    explicit = runner.invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(explicit_output),
            *_explicit_arguments(),
        ],
    )

    expected = b"#!AMR\n" + _storage_frame(fill=0x11)
    assert automatic.exit_code == 0
    assert explicit.exit_code == 0
    assert automatic_output.read_bytes() == expected
    assert explicit_output.read_bytes() == expected
    assert "passes=2" in automatic.output
    assert "passes=1" in explicit.output
    assert "bit-backend:" in explicit.output
    assert "frames: emitted=1" in explicit.output


def test_port_filter_writes_deterministically_named_ssrc_outputs(tmp_path: Path) -> None:
    capture = tmp_path / "multiple.pcap"
    output_dir = tmp_path / "outputs"
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(fill=0x11), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(fill=0x22), sequence=1, timestamp=0, ssrc=2)),
        ],
    )

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--src-port",
            "4000",
            "--dst-port",
            "5000",
            "--output-dir",
            str(output_dir),
        ],
    )

    first_name = cli_module._flow_filename(_selection(1))
    second_name = cli_module._flow_filename(_selection(2))
    assert result.exit_code == 0
    assert {path.name for path in output_dir.iterdir()} == {first_name, second_name}
    assert "src-192.0.2.1-4000__dst-192.0.2.2-5000__pt-96__ssrc-00000001" in first_name
    assert (output_dir / first_name).read_bytes() == b"#!AMR\n" + _storage_frame(fill=0x11)
    assert (output_dir / second_name).read_bytes() == b"#!AMR\n" + _storage_frame(fill=0x22)
    assert result.output.count("output: ") == 2


def test_ambiguity_renders_selectors_and_preserves_existing_output(tmp_path: Path) -> None:
    capture = tmp_path / "ambiguous.pcap"
    output = tmp_path / "existing.amr"
    output.write_bytes(b"existing")
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )

    result = CliRunner().invoke(
        cli,
        ["extract", str(capture), "--output", str(output)],
    )

    assert result.exit_code == 1
    assert "[ambiguous-selection]" in result.output
    assert "candidate selectors:" in result.output
    assert "--ssrc 1" in result.output
    assert "--ssrc 2" in result.output
    assert output.read_bytes() == b"existing"
    assert not tuple(tmp_path.glob(".existing.amr.*.tmp"))


def test_default_skip_commits_but_strict_failure_is_transactional(tmp_path: Path) -> None:
    capture = tmp_path / "malformed.pcap"
    skipped_output = tmp_path / "skipped.amr"
    strict_output = tmp_path / "strict.amr"
    strict_output.write_bytes(b"existing")
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
            _packet(_rtp(b"malformed", sequence=2, timestamp=160)),
            _packet(_rtp(_amr_payload(), sequence=3, timestamp=320)),
        ],
    )
    runner = CliRunner()

    skipped = runner.invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(skipped_output),
            *_explicit_arguments(),
        ],
    )
    strict = runner.invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(strict_output),
            "--malformed-policy",
            "strict",
            *_explicit_arguments(),
        ],
    )

    assert skipped.exit_code == 0
    assert skipped_output.read_bytes() == b"#!AMR\n" + _storage_frame() * 2
    assert "malformed=1" in skipped.output
    assert skipped.output.count("diagnostic:") == 1
    assert "diagnostics omitted:" not in skipped.output
    assert strict.exit_code == 1
    assert "[malformed-rfc4867]" in strict.output
    assert "capture packet 2" in strict.output
    assert strict_output.read_bytes() == b"existing"
    assert not tuple(tmp_path.glob(".strict.amr.*.tmp"))


def test_multiflow_strict_failure_removes_every_staged_output(tmp_path: Path) -> None:
    capture = tmp_path / "multi-failure.pcap"
    output_dir = tmp_path / "failed-outputs"
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
            _packet(_rtp(b"malformed", sequence=2, timestamp=160, ssrc=1)),
        ],
    )

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--src-port",
            "4000",
            "--dst-port",
            "5000",
            "--output-dir",
            str(output_dir),
            "--malformed-policy",
            "strict",
            "--max-samples-per-flow",
            "1",
        ],
    )

    assert result.exit_code == 1
    assert "[malformed-rfc4867]" in result.output
    assert tuple(output_dir.iterdir()) == ()


def test_multiflow_commit_failure_restores_every_existing_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = tmp_path / "commit-failure.pcap"
    output_dir = tmp_path / "existing-outputs"
    output_dir.mkdir()
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )
    first_output = output_dir / cli_module._flow_filename(_selection(1))
    second_output = output_dir / cli_module._flow_filename(_selection(2))
    first_output.write_bytes(b"old-first")
    second_output.write_bytes(b"old-second")
    original_replace = cli_module.os.replace
    failed = False

    def fail_second_install(source, destination):
        nonlocal failed
        if not failed and str(source).endswith(".tmp") and Path(destination) == second_output:
            failed = True
            raise OSError("simulated commit failure")
        return original_replace(source, destination)

    monkeypatch.setattr(cli_module.os, "replace", fail_second_install)

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--src-port",
            "4000",
            "--dst-port",
            "5000",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 1
    assert "simulated commit failure" in result.output
    assert first_output.read_bytes() == b"old-first"
    assert second_output.read_bytes() == b"old-second"
    assert {path.name for path in output_dir.iterdir()} == {
        first_output.name,
        second_output.name,
    }


def test_output_hard_link_to_capture_is_rejected(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcap"
    output = tmp_path / "capture-alias.amr"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    os.link(str(capture), str(output))
    capture_bytes = capture.read_bytes()

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(output),
            *_explicit_arguments(),
        ],
    )

    assert result.exit_code == 1
    assert "input and output paths must be different" in result.output
    assert capture.read_bytes() == capture_bytes
    assert output.read_bytes() == capture_bytes


def test_failed_rollback_preserves_the_original_output_backup(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = tmp_path / "rollback-failure.pcap"
    output_dir = tmp_path / "rollback-outputs"
    output_dir.mkdir()
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )
    first_output = output_dir / cli_module._flow_filename(_selection(1))
    second_output = output_dir / cli_module._flow_filename(_selection(2))
    first_output.write_bytes(b"old-first")
    second_output.write_bytes(b"old-second")
    original_replace = cli_module.os.replace
    install_failed = False

    def fail_install_and_restore(source, destination):
        nonlocal install_failed
        source_path = Path(source)
        destination_path = Path(destination)
        if (
            not install_failed
            and source_path.suffix == ".tmp"
            and destination_path == second_output
        ):
            install_failed = True
            raise OSError("simulated install failure")
        if install_failed and source_path.suffix == ".backup" and destination_path == second_output:
            raise OSError("simulated restore failure")
        return original_replace(source, destination)

    monkeypatch.setattr(cli_module.os, "replace", fail_install_and_restore)

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--src-port",
            "4000",
            "--dst-port",
            "5000",
            "--output-dir",
            str(output_dir),
        ],
    )

    backups = tuple(output_dir.glob(f".{second_output.name}.*.backup"))
    assert result.exit_code == 1
    assert "prior outputs could not be fully restored" in result.output
    assert first_output.read_bytes() == b"old-first"
    assert not second_output.exists()
    assert len(backups) == 1
    assert backups[0].read_bytes() == b"old-second"


def test_zero_diagnostics_is_valid_but_negative_is_rejected() -> None:
    assert ResourceLimits(max_diagnostics=0).max_diagnostics == 0

    with pytest.raises(ValueError, match="max_diagnostics must be at least 0"):
        ResourceLimits(max_diagnostics=-1)


def test_progress_builds_zero_diagnostic_options_and_preserves_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = _capture(tmp_path)
    received: List[InspectOptions] = []
    monkeypatch.setattr(cli_module, "_run_inspect", received.append)
    runner = CliRunner()

    progress_result = runner.invoke(cli, ["inspect", str(capture), "--progress"])
    default_result = runner.invoke(cli, ["inspect", str(capture)])

    assert progress_result.exit_code == 0
    assert default_result.exit_code == 0
    assert received[0].progress is True
    assert received[0].limits.max_diagnostics == 0
    assert received[1].progress is False
    assert received[1].limits.max_diagnostics == 1


@pytest.mark.parametrize(
    "arguments",
    (
        ["--progress", "--max-diagnostics", "1"],
        ["--max-diagnostics", "1", "--progress"],
    ),
)
@pytest.mark.parametrize("command", ["inspect", "extract"])
def test_progress_rejects_explicit_diagnostic_limit_before_processing(
    tmp_path: Path,
    monkeypatch,
    command: str,
    arguments: List[str],
) -> None:
    capture = _capture(tmp_path)
    output = tmp_path / "should-not-exist.amr"
    calls = []
    monkeypatch.setattr(cli_module, "_run_inspect", calls.append)
    monkeypatch.setattr(cli_module, "_run_extract", calls.append)
    command_arguments = [command, str(capture), *arguments]
    if command == "extract":
        command_arguments.extend(("--output", str(output)))

    result = CliRunner().invoke(cli, command_arguments)

    assert result.exit_code == 2
    assert "mutually exclusive" in result.output
    assert calls == []
    assert not output.exists()


def _force_terminal_progress(monkeypatch) -> None:
    monkeypatch.setattr(cli_module, "_is_terminal", lambda stream: True)
    monkeypatch.setattr(click_termui, "isatty", lambda stream: True)


@pytest.mark.parametrize("explicit", [False, True])
def test_progress_is_stderr_only_and_uses_planned_pass_count(
    tmp_path: Path,
    monkeypatch,
    explicit: bool,
) -> None:
    capture = tmp_path / "progress.pcap"
    output = tmp_path / "progress.amr"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    _force_terminal_progress(monkeypatch)
    created = []
    original_progress = cli_module.CaptureProgress

    class RecordingProgress(original_progress):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr(cli_module, "CaptureProgress", RecordingProgress)
    arguments = ["extract", str(capture), "--output", str(output), "--progress"]
    if explicit:
        arguments.extend(_explicit_arguments())

    result = CliRunner(mix_stderr=False).invoke(cli, arguments)

    expected_passes = 1 if explicit else 2
    assert result.exit_code == 0
    assert len(created) == 1
    assert created[0].pass_count == expected_passes
    assert created[0].completed_passes == expected_passes
    assert "Processing capture" in result.stderr
    assert "100%" in result.stderr
    assert "Processing capture" not in result.stdout
    assert f"passes={expected_passes}" in result.stdout


def test_progress_is_silent_when_stderr_is_not_a_terminal(tmp_path: Path) -> None:
    capture = tmp_path / "silent-progress.pcap"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )

    result = CliRunner(mix_stderr=False).invoke(
        cli,
        ["inspect", str(capture), "--progress"],
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    assert "capture: packets=1" in result.stdout


def test_progress_does_not_change_stdout_without_diagnostics(tmp_path: Path) -> None:
    capture = tmp_path / "same-report.pcap"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    runner = CliRunner(mix_stderr=False)

    normal = runner.invoke(cli, ["inspect", str(capture)])
    progress = runner.invoke(cli, ["inspect", str(capture), "--progress"])

    assert normal.exit_code == 0
    assert progress.exit_code == 0
    assert progress.stderr == ""
    normal_without_diagnostics = "\n".join(
        line
        for line in normal.stdout.splitlines()
        if not line.startswith(("diagnostic:", "diagnostics omitted:"))
    )
    assert progress.stdout.rstrip() == normal_without_diagnostics


def test_inspection_progress_reaches_100_percent_on_stderr(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = tmp_path / "inspection-progress.pcapng"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    _force_terminal_progress(monkeypatch)

    result = CliRunner(mix_stderr=False).invoke(
        cli,
        ["inspect", str(capture), "--progress"],
    )

    assert result.exit_code == 0
    assert "Processing capture" in result.stderr
    assert "100%" in result.stderr
    assert "capture: packets=1" in result.stdout


def test_progress_hides_diagnostics_but_keeps_aggregate_statistics(tmp_path: Path) -> None:
    capture = tmp_path / "progress-diagnostics.pcap"
    output = tmp_path / "progress-diagnostics.amr"
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
            _packet(_rtp(b"malformed", sequence=2, timestamp=160)),
        ],
    )

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(output),
            "--progress",
            *_explicit_arguments(),
        ],
    )

    assert result.exit_code == 0
    assert "malformed=1" in result.stdout
    assert "diagnostic:" not in result.stdout
    assert "diagnostics omitted:" not in result.stdout


def test_progress_hides_inspection_diagnostics_and_keeps_malformed_count(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "inspection-diagnostics.pcap"
    _write_capture(
        capture,
        [
            _packet(b"\x80\x60" + bytes(5)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
        ],
    )

    result = CliRunner().invoke(cli, ["inspect", str(capture), "--progress"])

    assert result.exit_code == 0
    assert "malformed-rtp=1" in result.stdout
    assert "diagnostic:" not in result.stdout
    assert "diagnostics omitted:" not in result.stdout


def test_non_progress_mode_still_retains_one_diagnostic(tmp_path: Path) -> None:
    capture = tmp_path / "default-diagnostics.pcap"
    _write_capture(
        capture,
        [
            _packet(b"\x80\x60" + bytes(5)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
        ],
    )

    result = CliRunner().invoke(cli, ["inspect", str(capture)])

    assert result.exit_code == 0
    assert result.stdout.count("diagnostic:") == 1
    assert "diagnostics omitted:" in result.stdout


def test_ambiguity_leaves_two_pass_progress_partial_and_preserves_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = tmp_path / "progress-ambiguity.pcap"
    output = tmp_path / "existing.amr"
    output.write_bytes(b"existing")
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )
    _force_terminal_progress(monkeypatch)

    result = CliRunner(mix_stderr=False).invoke(
        cli,
        ["extract", str(capture), "--output", str(output), "--progress"],
    )

    assert result.exit_code == 1
    assert "50%" in result.stderr
    assert "100%" not in result.stderr
    assert output.read_bytes() == b"existing"
    assert not tuple(tmp_path.glob(".existing.amr.*.tmp"))


def test_strict_failure_leaves_progress_partial_and_preserves_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = tmp_path / "progress-strict.pcap"
    output = tmp_path / "existing.amr"
    output.write_bytes(b"existing")
    _write_capture(
        capture,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
            _packet(_rtp(b"malformed", sequence=2, timestamp=160)),
        ],
    )
    _force_terminal_progress(monkeypatch)

    result = CliRunner(mix_stderr=False).invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(output),
            "--progress",
            "--malformed-policy",
            "strict",
            *_explicit_arguments(),
        ],
    )

    assert result.exit_code == 1
    assert "100%" not in result.stderr
    assert output.read_bytes() == b"existing"
    assert not tuple(tmp_path.glob(".existing.amr.*.tmp"))


def test_compressed_progress_fails_before_output_staging(tmp_path: Path) -> None:
    capture = tmp_path / "source.pcap"
    compressed = tmp_path / "source.pcap.gz"
    output = tmp_path / "existing.amr"
    output.write_bytes(b"existing")
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    with gzip.open(str(compressed), "wb") as destination:
        destination.write(capture.read_bytes())

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(compressed),
            "--output",
            str(output),
            "--progress",
            *_explicit_arguments(),
        ],
    )

    assert result.exit_code == 1
    assert "compressed capture" in result.output
    assert output.read_bytes() == b"existing"
    assert not tuple(tmp_path.glob(".existing.amr.*.tmp"))


def test_compressed_progress_fails_before_output_directory_creation(tmp_path: Path) -> None:
    capture = tmp_path / "source.pcap"
    compressed = tmp_path / "source.pcap.gz"
    output_dir = tmp_path / "outputs"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    with gzip.open(str(compressed), "wb") as destination:
        destination.write(capture.read_bytes())

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(compressed),
            "--src-port",
            "4000",
            "--output-dir",
            str(output_dir),
            "--progress",
        ],
    )

    assert result.exit_code == 1
    assert "compressed capture" in result.output
    assert not output_dir.exists()


def test_non_regular_progress_fails_before_output_staging(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    capture = tmp_path / "capture.fifo"
    output = tmp_path / "existing.amr"
    os.mkfifo(str(capture))
    output.write_bytes(b"existing")

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(output),
            "--progress",
            *_explicit_arguments(),
        ],
    )

    assert result.exit_code == 1
    assert "regular capture" in result.output
    assert output.read_bytes() == b"existing"
    assert not tuple(tmp_path.glob(".existing.amr.*.tmp"))


def test_progress_render_failure_preserves_existing_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = tmp_path / "render-failure.pcap"
    output = tmp_path / "existing.amr"
    output.write_bytes(b"existing")
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    _force_terminal_progress(monkeypatch)

    class FailingRenderer:
        def __init__(self, bar, total: int) -> None:
            del bar, total

        def advance(self, amount: int) -> None:
            del amount

        def flush(self) -> None:
            raise OSError("simulated progress output failure")

    monkeypatch.setattr(cli_module, "_ByteProgressRenderer", FailingRenderer)

    result = CliRunner().invoke(
        cli,
        [
            "extract",
            str(capture),
            "--output",
            str(output),
            "--progress",
            *_explicit_arguments(),
        ],
    )

    assert result.exit_code == 1
    assert "[progress-output]" in result.output
    assert output.read_bytes() == b"existing"
    assert not tuple(tmp_path.glob(".existing.amr.*.tmp"))
