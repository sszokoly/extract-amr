"""Streaming inspection and extraction API integration tests."""

import io
import os
import struct
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from extract_amr import api
from extract_amr.capture import CaptureProgress
from extract_amr.discovery import candidate_identifier
from extract_amr.errors import CaptureInputError, Rfc4867Error, SelectionError
from extract_amr.models import (
    Codec,
    FlowKey,
    FlowSelector,
    MalformedPolicy,
    PayloadMode,
    ResourceLimits,
    SelectedFlow,
)


def _speech_data(bit_count: int, fill: int) -> bytes:
    byte_count = (bit_count + 7) // 8
    data = bytearray([fill] * byte_count)
    padding = byte_count * 8 - bit_count
    if padding:
        data[-1] &= 0xFF << padding
    return bytes(data)


def _amr_payload(
    *,
    frame_type: int = 1,
    quality: bool = True,
    fill: int = 0,
) -> bytes:
    bit_counts = (95, 103, 118, 134, 148, 159, 204, 244, 39)
    bit_count = bit_counts[frame_type]
    toc = (frame_type << 3) | (int(quality) << 2)
    return bytes([0xF0, toc]) + _speech_data(bit_count, fill)


def _rtp(
    payload: bytes,
    *,
    sequence: int,
    timestamp: int,
    ssrc: int = 1,
    payload_type: int = 96,
) -> bytes:
    return (
        struct.pack(
            "!BBHII",
            0x80,
            payload_type,
            sequence,
            timestamp,
            ssrc,
        )
        + payload
    )


def _packet(
    payload: bytes,
    *,
    src_address: str = "192.0.2.1",
    dst_address: str = "192.0.2.2",
    src_port: int = 4000,
    dst_port: int = 5000,
):
    return (
        Ether()
        / IP(src=src_address, dst=dst_address)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(payload)
    )


def _write_capture(path: Path, packets) -> None:
    writer = PcapWriter(str(path), linktype=1, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def _flow(ssrc: int = 1, payload_type: int = 96) -> FlowKey:
    return FlowKey(
        "192.0.2.1",
        "192.0.2.2",
        4000,
        5000,
        ssrc,
        payload_type,
    )


def _selector(ssrc: int = 1, payload_type: int = 96) -> FlowSelector:
    key = _flow(ssrc, payload_type)
    return FlowSelector(
        src_address=key.src_address,
        dst_address=key.dst_address,
        src_port=key.src_port,
        dst_port=key.dst_port,
        ssrc=key.ssrc,
        payload_type=key.payload_type,
    )


def _selection(ssrc: int = 1, payload_type: int = 96) -> SelectedFlow:
    return SelectedFlow(
        candidate_id=f"flow-{ssrc}",
        flow_key=_flow(ssrc, payload_type),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
        first_packet_number=1,
    )


def _storage_frame(
    *,
    frame_type: int = 1,
    quality: bool = True,
    fill: int = 0,
) -> bytes:
    payload = _amr_payload(frame_type=frame_type, quality=quality, fill=fill)
    header = (frame_type << 3) | (int(quality) << 2)
    return bytes([header]) + payload[2:]


def test_inspect_pcap_streams_candidates_and_statistics(tmp_path: Path) -> None:
    path = tmp_path / "inspect.pcap"
    malformed_rtp = b"\x80\x60" + bytes(5)
    packets = [
        Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(),
        _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
        _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        _packet(malformed_rtp),
    ]
    _write_capture(path, packets)

    report = api.inspect_pcap(path)

    assert report.capture_packet_count == 4
    assert report.udp_packet_count == 3
    assert report.rtp_packet_count == 2
    assert report.malformed_rtp_count == 1
    assert len(report.valid_candidates) == 2
    assert [candidate.flow_key.ssrc for candidate in report.candidates] == [1, 2]
    assert report.diagnostics[0].provenance.packet_number == 4


def test_iter_frames_needs_no_storage_writer(tmp_path: Path) -> None:
    path = tmp_path / "frames.pcap"
    packets = [
        _packet(
            _rtp(
                _amr_payload(quality=False, fill=0x11),
                sequence=1,
                timestamp=0,
            ),
        ),
        _packet(
            _rtp(
                _amr_payload(quality=True, fill=0x22),
                sequence=2,
                timestamp=160,
            ),
        ),
    ]
    _write_capture(path, packets)

    frames = list(api.iter_frames(path, _selection()))

    assert [frame.media_timestamp for frame in frames] == [0, 160]
    assert [frame.quality for frame in frames] == [False, True]
    assert frames[0].data == _speech_data(103, 0x11)


@pytest.mark.parametrize("policy", list(MalformedPolicy))
def test_q_zero_is_valid_under_both_malformed_policies(
    tmp_path: Path,
    policy: MalformedPolicy,
) -> None:
    path = tmp_path / f"q0-{policy.value}.pcap"
    _write_capture(
        path,
        [
            _packet(
                _rtp(
                    _amr_payload(quality=False),
                    sequence=1,
                    timestamp=0,
                ),
            ),
        ],
    )
    output = io.BytesIO()

    report = api.extract_pcap(
        path,
        output,
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
        malformed_policy=policy,
    )

    assert report.bad_quality_frame_count == 1
    assert report.malformed_packet_count == 0
    assert output.getvalue() == b"#!AMR\n" + _storage_frame(quality=False)


def test_complete_selection_extracts_in_one_pass_to_caller_stream(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "explicit.pcap"
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(fill=0x11), sequence=1, timestamp=0)),
            _packet(_rtp(_amr_payload(fill=0x22), sequence=2, timestamp=160)),
        ],
    )
    calls = 0
    original = api.iter_udp_records

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(api, "iter_udp_records", counted)
    output = io.BytesIO()

    report = api.extract_pcap(
        path,
        output,
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
    )

    assert calls == 1
    assert report.capture_pass_count == 1
    assert report.capture_packet_count == 2
    assert report.selected_rtp_packet_count == 2
    assert report.emitted_frame_count == 2
    assert report.output_path is None
    assert not output.closed
    assert output.getvalue() == (b"#!AMR\n" + _storage_frame(fill=0x11) + _storage_frame(fill=0x22))


def test_extraction_retries_short_stream_writes(tmp_path: Path) -> None:
    path = tmp_path / "short-writes.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(fill=0x11), sequence=1, timestamp=0))],
    )

    class ShortWriter:
        def __init__(self) -> None:
            self.data = bytearray()

        def write(self, data) -> int:
            self.data.extend(data[:1])
            return 1

    output = ShortWriter()

    report = api.extract_pcap(
        path,
        output,
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
    )

    assert report.emitted_frame_count == 1
    assert bytes(output.data) == b"#!AMR\n" + _storage_frame(fill=0x11)


def test_explicit_extraction_progress_accounts_for_one_pass(tmp_path: Path) -> None:
    path = tmp_path / "explicit-progress.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    deltas = []
    progress = CaptureProgress(path, 1, deltas.append)

    report = api.extract_pcap(
        path,
        io.BytesIO(),
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
        _progress=progress,
    )
    progress.ensure_complete()

    assert report.capture_pass_count == 1
    assert progress.completed_passes == 1
    assert sum(deltas) == path.stat().st_size


def test_automatic_selection_uses_exactly_two_passes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "automatic.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    calls = 0
    original = api.iter_udp_records

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(api, "iter_udp_records", counted)

    report = api.extract_pcap(path, io.BytesIO())

    assert calls == 2
    assert report.capture_pass_count == 2
    assert report.selected_flow.flow_key == _flow()


def test_automatic_extraction_progress_accounts_for_two_passes(tmp_path: Path) -> None:
    path = tmp_path / "automatic-progress.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    deltas = []
    progress = CaptureProgress(path, 2, deltas.append)

    report = api.extract_pcap(path, io.BytesIO(), _progress=progress)
    progress.ensure_complete()

    assert report.capture_pass_count == 2
    assert progress.completed_passes == 2
    assert sum(deltas) == 2 * path.stat().st_size


def test_nonreopenable_input_requires_complete_selection(tmp_path: Path) -> None:
    path = tmp_path / "stream.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    source = io.BytesIO(path.read_bytes())

    with pytest.raises(CaptureInputError, match="reopenable capture path"):
        api.extract_pcap(source, io.BytesIO())


def test_explicit_nonreopenable_input_remains_one_pass(tmp_path: Path) -> None:
    path = tmp_path / "explicit-stream.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )

    source = io.BytesIO(path.read_bytes())
    report = api.extract_pcap(
        source,
        io.BytesIO(),
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
    )

    assert report.capture_pass_count == 1
    assert report.emitted_frame_count == 1
    assert not source.closed


def test_caller_owned_capture_streams_remain_open(tmp_path: Path) -> None:
    path = tmp_path / "owned-input.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    capture_bytes = path.read_bytes()
    inspection_source = io.BytesIO(capture_bytes)
    frame_source = io.BytesIO(capture_bytes)

    api.inspect_pcap(inspection_source)
    list(api.iter_frames(frame_source, _selection()))

    assert not inspection_source.closed
    assert not frame_source.closed


def test_all_invalid_explicit_payloads_fail_selection(tmp_path: Path) -> None:
    path = tmp_path / "wrong-format.pcap"
    _write_capture(
        path,
        [_packet(_rtp(b"malformed", sequence=1, timestamp=0))],
    )
    output = io.BytesIO()

    with pytest.raises(SelectionError, match="no payload valid"):
        api.extract_pcap(
            path,
            output,
            selector=_selector(),
            codec=Codec.AMR,
            payload_mode=PayloadMode.OCTET_ALIGNED,
        )

    assert output.getvalue() == b"#!AMR\n"


def test_path_output_is_rejected_without_modifying_existing_file(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcap"
    output = tmp_path / "existing.amr"
    _write_capture(
        capture,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    output.write_bytes(b"existing")

    with pytest.raises(ValueError, match="caller-owned writable binary stream"):
        api.extract_pcap(
            capture,
            output,
            selector=_selector(),
            codec=Codec.AMR,
            payload_mode=PayloadMode.OCTET_ALIGNED,
        )

    assert output.read_bytes() == b"existing"


def test_default_skip_omits_malformed_payload_and_reports_it(tmp_path: Path) -> None:
    path = tmp_path / "skip.pcap"
    packets = [
        _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
        _packet(_rtp(b"malformed", sequence=2, timestamp=160)),
        _packet(_rtp(_amr_payload(), sequence=3, timestamp=320)),
    ]
    _write_capture(path, packets)
    output = io.BytesIO()

    report = api.extract_pcap(
        path,
        output,
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
    )

    assert report.malformed_packet_count == 1
    assert report.emitted_frame_count == 2
    assert report.diagnostics[0].provenance.packet_number == 2
    assert output.getvalue() == b"#!AMR\n" + _storage_frame() * 2


def test_zero_diagnostic_limit_retains_only_aggregate_statistics(tmp_path: Path) -> None:
    path = tmp_path / "zero-diagnostics.pcap"
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
            _packet(_rtp(b"malformed", sequence=2, timestamp=160)),
        ],
    )

    inspection = api.inspect_pcap(path, limits=ResourceLimits(max_diagnostics=0))
    report = api.extract_pcap(
        path,
        io.BytesIO(),
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
        limits=ResourceLimits(max_diagnostics=0),
    )

    assert inspection.diagnostics == ()
    assert inspection.diagnostic_overflow_count > 0
    assert report.diagnostics == ()
    assert report.diagnostic_overflow_count == 1
    assert report.malformed_packet_count == 1


def test_progress_rejects_capture_changed_between_discovery_and_extraction(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "changing.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )
    progress = CaptureProgress(path, 2)
    original_inspect = api.inspect_pcap
    original_stat = path.stat()

    def inspect_then_change(*args, **kwargs):
        report = original_inspect(*args, **kwargs)
        changed = bytearray(path.read_bytes())
        changed[-1] ^= 0x01
        path.write_bytes(changed)
        os.utime(
            str(path),
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        return report

    monkeypatch.setattr(api, "inspect_pcap", inspect_then_change)

    with pytest.raises(CaptureInputError, match="capture changed"):
        api.extract_pcap(path, io.BytesIO(), _progress=progress)


def test_strict_policy_raises_without_serializing_invalid_payload(tmp_path: Path) -> None:
    path = tmp_path / "strict.pcap"
    packets = [
        _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
        _packet(_rtp(b"malformed", sequence=2, timestamp=160)),
    ]
    _write_capture(path, packets)
    output = io.BytesIO()

    with pytest.raises(Rfc4867Error, match="padding bits are non-zero"):
        api.extract_pcap(
            path,
            output,
            selector=_selector(),
            codec=Codec.AMR,
            payload_mode=PayloadMode.OCTET_ALIGNED,
            malformed_policy=MalformedPolicy.STRICT,
        )

    assert output.getvalue() == b"#!AMR\n"


def test_extraction_report_contains_timeline_and_backend_statistics(tmp_path: Path) -> None:
    path = tmp_path / "report.pcap"
    first = _rtp(
        _amr_payload(quality=False),
        sequence=1,
        timestamp=0,
    )
    packets = [
        _packet(first),
        _packet(first),
        _packet(_rtp(_amr_payload(), sequence=3, timestamp=320)),
        _packet(_rtp(_amr_payload(), sequence=2, timestamp=160)),
        _packet(_rtp(_amr_payload(), sequence=4, timestamp=640)),
        _packet(_rtp(b"malformed", sequence=5, timestamp=800)),
    ]
    _write_capture(path, packets)

    report = api.extract_pcap(
        path,
        io.BytesIO(),
        selector=_selector(),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
        limits=ResourceLimits(reorder_window=2),
    )

    assert report.capture_packet_count == 6
    assert report.udp_packet_count == 6
    assert report.selected_rtp_packet_count == 6
    assert report.emitted_frame_count == 4
    assert report.bad_quality_frame_count == 1
    assert report.duplicate_packet_count == 1
    assert report.gap_count == 1
    assert report.reordered_packet_count == 1
    assert report.late_packet_count == 0
    assert report.malformed_packet_count == 1
    assert report.bit_backend in {"python", "bitarray"}
    assert report.diagnostics
    assert report.selected_flow.first_packet_number == 1
    assert report.selected_flow.candidate_id == candidate_identifier(_flow(), 1)


def test_extract_flows_writes_independent_ssrc_outputs(tmp_path: Path) -> None:
    path = tmp_path / "multiple.pcap"
    first_flow_packet = _rtp(
        _amr_payload(fill=0x11),
        sequence=1,
        timestamp=0,
        ssrc=1,
    )
    packets = [
        _packet(first_flow_packet),
        _packet(first_flow_packet),
        _packet(
            _rtp(
                _amr_payload(fill=0x22),
                sequence=1,
                timestamp=1000,
                ssrc=2,
            ),
        ),
    ]
    _write_capture(path, packets)
    outputs = {_flow(1): io.BytesIO(), _flow(2): io.BytesIO()}

    reports = api.extract_flows(
        path,
        outputs,
        selector=FlowSelector(src_port=4000, dst_port=5000),
    )

    assert len(reports) == 2
    by_ssrc = {report.selected_flow.flow_key.ssrc: report for report in reports}
    assert by_ssrc[1].duplicate_packet_count == 1
    assert by_ssrc[2].duplicate_packet_count == 0
    assert all(report.capture_pass_count == 2 for report in reports)
    assert outputs[_flow(1)].getvalue() == b"#!AMR\n" + _storage_frame(fill=0x11)
    assert outputs[_flow(2)].getvalue() == b"#!AMR\n" + _storage_frame(fill=0x22)


def test_extract_flows_uses_two_actual_capture_passes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "flow-passes.pcap"
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )
    calls = 0
    original = api.iter_udp_records

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(api, "iter_udp_records", counted)
    outputs = {_flow(1): io.BytesIO(), _flow(2): io.BytesIO()}

    api.extract_flows(
        path,
        outputs,
        selector=FlowSelector(src_port=4000, dst_port=5000),
    )

    assert calls == 2


def test_extract_flows_progress_accounts_for_shared_two_passes(tmp_path: Path) -> None:
    path = tmp_path / "flow-progress.pcap"
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )
    outputs = {_flow(1): io.BytesIO(), _flow(2): io.BytesIO()}
    deltas = []
    progress = CaptureProgress(path, 2, deltas.append)

    reports = api.extract_flows(
        path,
        outputs,
        selector=FlowSelector(src_port=4000, dst_port=5000),
        _progress=progress,
    )
    progress.ensure_complete()

    assert len(reports) == 2
    assert progress.completed_passes == 2
    assert sum(deltas) == 2 * path.stat().st_size


def test_extract_flows_output_factory_receives_resolved_selections(
    tmp_path: Path,
) -> None:
    path = tmp_path / "flow-factory.pcap"
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )
    outputs = {}

    def output_for(selection: SelectedFlow):
        output = io.BytesIO()
        outputs[selection.flow_key] = output
        return output

    reports = api.extract_flows(
        path,
        output_for,
        selector=FlowSelector(src_port=4000, dst_port=5000),
    )

    assert [report.selected_flow.flow_key.ssrc for report in reports] == [1, 2]
    assert set(outputs) == {_flow(1), _flow(2)}
    assert all(output.getvalue().startswith(b"#!AMR\n") for output in outputs.values())


def test_extract_flows_rejects_shared_output_stream(tmp_path: Path) -> None:
    path = tmp_path / "shared-output.pcap"
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
        ],
    )
    shared = io.BytesIO()

    with pytest.raises(SelectionError, match="independent output stream"):
        api.extract_flows(
            path,
            {_flow(1): shared, _flow(2): shared},
            selector=FlowSelector(src_port=4000, dst_port=5000),
        )

    assert shared.getvalue() == b""


def test_malformed_rtp_is_attributed_only_to_its_full_flow(tmp_path: Path) -> None:
    path = tmp_path / "malformed-attribution.pcap"
    extension_truncated = struct.pack(
        "!BBHIIHH",
        0x90,
        96,
        9,
        0,
        1,
        0xBEDE,
        1,
    )
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
            _packet(extension_truncated),
        ],
    )
    outputs = {_flow(1): io.BytesIO(), _flow(2): io.BytesIO()}

    reports = api.extract_flows(
        path,
        outputs,
        selector=FlowSelector(src_port=4000, dst_port=5000),
    )

    by_ssrc = {report.selected_flow.flow_key.ssrc: report for report in reports}
    assert by_ssrc[1].malformed_packet_count == 1
    assert by_ssrc[2].malformed_packet_count == 0
    assert by_ssrc[1].diagnostics[0].provenance.packet_number == 3


def test_unattributed_malformed_rtp_does_not_cross_contaminate_flows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unattributed-malformed.pcap"
    _write_capture(
        path,
        [
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=1)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0, ssrc=2)),
            _packet(b"\x80\x60" + bytes(5)),
        ],
    )
    outputs = {_flow(1): io.BytesIO(), _flow(2): io.BytesIO()}

    reports = api.extract_flows(
        path,
        outputs,
        selector=FlowSelector(src_port=4000, dst_port=5000),
        malformed_policy=MalformedPolicy.STRICT,
    )

    assert all(report.malformed_packet_count == 0 for report in reports)


def test_inspection_uses_one_aggregate_diagnostic_limit(tmp_path: Path) -> None:
    path = tmp_path / "diagnostic-limit.pcap"
    _write_capture(
        path,
        [
            _packet(b"\x80\x60" + bytes(5)),
            _packet(_rtp(_amr_payload(), sequence=1, timestamp=0)),
        ],
    )

    report = api.inspect_pcap(path, limits=ResourceLimits(max_diagnostics=2))

    assert len(report.diagnostics) == 2
    assert report.diagnostic_overflow_count == 2
    assert report.discovery.diagnostics == ()
    assert report.discovery.diagnostic_overflow_count == 2


def test_nonreopenable_multi_flow_discovery_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "nonreopenable-flows.pcap"
    _write_capture(
        path,
        [_packet(_rtp(_amr_payload(), sequence=1, timestamp=0))],
    )

    with pytest.raises(CaptureInputError, match="reopenable capture path"):
        api.extract_flows(
            io.BytesIO(path.read_bytes()),
            {_flow(): io.BytesIO()},
            selector=FlowSelector(src_port=4000),
        )


def test_repeated_extractions_start_with_independent_state(tmp_path: Path) -> None:
    path = tmp_path / "repeat.pcap"
    packet = _packet(_rtp(_amr_payload(), sequence=1, timestamp=0))
    _write_capture(path, [packet, packet])
    outputs = [io.BytesIO(), io.BytesIO()]

    reports = [
        api.extract_pcap(
            path,
            output,
            selector=_selector(),
            codec=Codec.AMR,
            payload_mode=PayloadMode.OCTET_ALIGNED,
        )
        for output in outputs
    ]

    assert outputs[0].getvalue() == outputs[1].getvalue()
    assert reports[0].duplicate_packet_count == reports[1].duplicate_packet_count == 1
    assert reports[0].emitted_frame_count == reports[1].emitted_frame_count == 1
