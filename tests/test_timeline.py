"""RTP rollover, reordering, overlap, gap, and per-flow timeline tests."""

from dataclasses import replace
from decimal import Decimal
from itertools import islice

import pytest

from extract_amr.codec import AMR_DEFINITION, AMR_WB_DEFINITION
from extract_amr.errors import Rfc4867Error
from extract_amr.models import (
    CaptureProvenance,
    Codec,
    FlowKey,
    GapPolicy,
    PayloadMode,
    ResourceLimits,
    RtpRecord,
    SelectedFlow,
)
from extract_amr.timeline import TimelineNormalizer, TimelineRouter


AMR_FLOW = FlowKey("192.0.2.1", "192.0.2.2", 4000, 5000, 1, 96)
WB_FLOW = FlowKey("192.0.2.1", "192.0.2.2", 4000, 5000, 2, 97)


def _frame_data(bit_count: int, fill: int) -> bytes:
    byte_count = (bit_count + 7) // 8
    if byte_count == 0:
        return b""
    data = bytearray([fill] * byte_count)
    padding = byte_count * 8 - bit_count
    if padding:
        data[-1] &= 0xFF << padding
    return bytes(data)


def _payload(codec: Codec, entries) -> bytes:
    definition = AMR_DEFINITION if codec is Codec.AMR else AMR_WB_DEFINITION
    toc = bytearray()
    speech = bytearray()
    for index, (frame_type, quality, fill) in enumerate(entries):
        followed = index < len(entries) - 1
        toc.append((int(followed) << 7) | (frame_type << 3) | (int(quality) << 2))
        bit_count = definition.bit_count(frame_type)
        assert bit_count is not None
        speech.extend(_frame_data(bit_count, fill))
    return b"\xf0" + bytes(toc) + bytes(speech)


def _pack(bit_string: str) -> bytes:
    padded = bit_string + "0" * (-len(bit_string) % 8)
    return int(padded, 2).to_bytes(len(padded) // 8, "big")


def _bandwidth_payload(codec: Codec, entries) -> bytes:
    definition = AMR_DEFINITION if codec is Codec.AMR else AMR_WB_DEFINITION
    fields = ["1111"]
    speech = []
    for index, (frame_type, quality, fill) in enumerate(entries):
        followed = index < len(entries) - 1
        fields.append(f"{int(followed)}{frame_type:04b}{int(quality)}")
        bit_count = definition.bit_count(frame_type)
        assert bit_count is not None
        data = _frame_data(bit_count, fill)
        speech.append("".join(f"{byte:08b}" for byte in data)[:bit_count])
    return _pack("".join(fields + speech))


def _record(
    sequence: int,
    timestamp: int,
    packet_number: int,
    *,
    flow_key: FlowKey = AMR_FLOW,
    codec: Codec = Codec.AMR,
    entries=((1, True, 0x00),),
) -> RtpRecord:
    return RtpRecord(
        flow_key=flow_key,
        sequence=sequence,
        timestamp=timestamp,
        marker=False,
        payload=_payload(codec, entries),
        provenance=CaptureProvenance(
            packet_number,
            Decimal(packet_number) / Decimal(10),
        ),
    )


def _normalizer(
    *,
    flow_key: FlowKey = AMR_FLOW,
    codec: Codec = Codec.AMR,
    gap_policy: GapPolicy = GapPolicy.OMIT,
    reorder_window: int = 2,
    max_diagnostics: int = 100,
) -> TimelineNormalizer:
    return TimelineNormalizer(
        flow_key,
        codec,
        PayloadMode.OCTET_ALIGNED,
        gap_policy=gap_policy,
        limits=ResourceLimits(
            reorder_window=reorder_window,
            max_diagnostics=max_diagnostics,
        ),
    )


def _run(normalizer: TimelineNormalizer, records) -> list:
    frames = []
    for record in records:
        frames.extend(normalizer.push(record))
    frames.extend(normalizer.finish())
    return frames


def test_extends_sequence_and_timestamp_rollover() -> None:
    normalizer = _normalizer()
    frames = _run(
        normalizer,
        [
            _record(65535, 0xFFFFFF60, 1),
            _record(0, 0, 2),
        ],
    )

    assert [frame.media_timestamp for frame in frames] == [0xFFFFFF60, 0x100000000]
    assert normalizer.summary.highest_extended_sequence == 65536
    assert normalizer.summary.highest_extended_timestamp == 0x100000000
    assert normalizer.summary.gap_count == 0


def test_duplicate_packet_is_suppressed_before_depacketization(monkeypatch) -> None:
    normalizer = _normalizer()
    valid = _record(1, 0, 1)
    duplicate = RtpRecord(
        flow_key=valid.flow_key,
        sequence=valid.sequence,
        timestamp=valid.timestamp,
        marker=valid.marker,
        payload=valid.payload,
        provenance=CaptureProvenance(2, Decimal("0.2")),
    )
    from extract_amr import timeline

    calls = 0
    original = timeline.depacketize

    def counted_depacketize(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(timeline, "depacketize", counted_depacketize)

    frames = _run(normalizer, [valid, duplicate])

    assert len(frames) == 1
    assert calls == 1
    assert normalizer.summary.packet_count == 2
    assert normalizer.summary.accepted_packet_count == 1
    assert normalizer.summary.duplicate_packet_count == 1


def test_reused_sequence_with_different_packet_content_is_not_a_duplicate() -> None:
    normalizer = _normalizer(reorder_window=4)
    first = _record(1, 0, 1, entries=((1, True, 0x11),))
    corrected = _record(1, 0, 2, entries=((1, True, 0x22),))

    frames = _run(normalizer, [first, corrected])

    assert len(frames) == 1
    assert normalizer.summary.accepted_packet_count == 2
    assert normalizer.summary.duplicate_packet_count == 0
    assert normalizer.summary.overlap_frame_count == 1


def test_bounded_history_recognizes_a_b_a_duplicate_sequence_pattern() -> None:
    normalizer = _normalizer(reorder_window=4)
    first = _record(1, 0, 1, entries=((1, True, 0x11),))
    corrected = _record(1, 0, 2, entries=((1, True, 0x22),))
    repeated_first = replace(
        first,
        provenance=CaptureProvenance(3, Decimal("0.3")),
    )

    frames = _run(normalizer, [first, corrected, repeated_first])

    assert len(frames) == 1
    assert normalizer.summary.accepted_packet_count == 2
    assert normalizer.summary.duplicate_packet_count == 1
    assert normalizer.summary.overlap_frame_count == 1


def test_duplicate_history_survives_versions_inside_small_reorder_window() -> None:
    normalizer = _normalizer(reorder_window=2)
    first = _record(1, 0, 1, entries=((1, True, 0x11),))
    corrected = _record(1, 0, 2, entries=((1, True, 0x22),))
    next_interval = _record(2, 160, 3)
    repeated_first = replace(
        first,
        provenance=CaptureProvenance(4, Decimal("0.4")),
    )

    _run(normalizer, [first, corrected, next_interval, repeated_first])

    assert normalizer.summary.accepted_packet_count == 3
    assert normalizer.summary.duplicate_packet_count == 1


def test_duplicate_history_overflow_fails_closed_without_forgetting_packets() -> None:
    normalizer = _normalizer(reorder_window=1)
    versions = [_record(1, 0, packet, entries=((1, True, packet),)) for packet in range(1, 7)]
    repeated_first = replace(
        versions[0],
        provenance=CaptureProvenance(7, Decimal("0.7")),
    )

    frames = _run(normalizer, versions + [repeated_first])

    assert len(frames) == 1
    assert normalizer.summary.accepted_packet_count == 4
    assert normalizer.summary.packet_history_overflow_count == 2
    assert normalizer.summary.duplicate_packet_count == 1
    assert any(
        diagnostic.reason == "packet-history-overflow"
        for diagnostic in normalizer.summary.diagnostics
    )


def test_compound_packet_identity_remains_until_its_last_frame_commits() -> None:
    normalizer = _normalizer(reorder_window=1)
    compound = _record(
        1,
        0,
        1,
        entries=((1, True, 0x11), (1, True, 0x22), (1, True, 0x33)),
    )
    first_output = list(normalizer.push(compound))
    duplicate = replace(
        compound,
        provenance=CaptureProvenance(2, Decimal("0.2")),
    )

    duplicate_output = list(normalizer.push(duplicate))
    remaining = list(normalizer.finish())

    assert [frame.media_timestamp for frame in first_output] == [0, 160]
    assert duplicate_output == []
    assert [frame.media_timestamp for frame in remaining] == [320]
    assert normalizer.summary.accepted_packet_count == 1
    assert normalizer.summary.duplicate_packet_count == 1
    assert normalizer.summary.late_packet_count == 0


def test_duplicate_identity_includes_normalized_rtp_metadata() -> None:
    normalizer = _normalizer(reorder_window=4)
    first = _record(1, 0, 1)
    different_extension = replace(
        first,
        provenance=CaptureProvenance(2, Decimal("0.2")),
        extension_profile=0xBEDE,
        extension_data=b"abcd",
    )
    repeated_first = replace(
        first,
        provenance=CaptureProvenance(3, Decimal("0.3")),
    )

    _run(normalizer, [first, different_extension, repeated_first])

    assert normalizer.summary.accepted_packet_count == 2
    assert normalizer.summary.duplicate_packet_count == 1


def test_reorders_packets_inside_the_media_watermark() -> None:
    normalizer = _normalizer(reorder_window=2)
    records = [
        _record(1, 0, 1),
        _record(3, 320, 2),
        _record(2, 160, 3),
    ]

    first = list(normalizer.push(records[0]))
    second = list(normalizer.push(records[1]))
    third = list(normalizer.push(records[2]))
    remaining = list(normalizer.finish())

    assert first == []
    assert [frame.media_timestamp for frame in second] == [0]
    assert third == []
    assert [frame.media_timestamp for frame in remaining] == [160, 320]
    assert normalizer.summary.reordered_packet_count == 1


def test_delayed_pre_wrap_packet_is_extended_before_post_wrap_start() -> None:
    normalizer = _normalizer(reorder_window=4)
    post_wrap = _record(0, 0, 1)
    delayed_pre_wrap = _record(65535, 0xFFFFFF60, 2)

    frames = _run(normalizer, [post_wrap, delayed_pre_wrap])

    assert [frame.media_timestamp for frame in frames] == [-160, 0]
    assert normalizer.summary.highest_extended_sequence == 0
    assert normalizer.summary.highest_extended_timestamp == 0
    assert normalizer.summary.reordered_packet_count == 1


@pytest.mark.parametrize(
    ("codec", "flow_key", "step"),
    [
        (Codec.AMR, AMR_FLOW, 160),
        (Codec.AMR_WB, WB_FLOW, 320),
    ],
)
def test_compound_payload_frames_advance_by_twenty_milliseconds(
    codec: Codec,
    flow_key: FlowKey,
    step: int,
) -> None:
    normalizer = _normalizer(flow_key=flow_key, codec=codec)
    frame_type = 1
    record = _record(
        1,
        1000,
        1,
        flow_key=flow_key,
        codec=codec,
        entries=(
            (frame_type, True, 0x00),
            (frame_type, True, 0x11),
            (frame_type, True, 0x22),
        ),
    )

    frames = _run(normalizer, [record])

    assert [frame.media_timestamp for frame in frames] == [1000, 1000 + step, 1000 + 2 * step]
    assert normalizer.summary.observed_frame_count == 3


def test_bandwidth_efficient_compound_frames_use_the_same_timeline() -> None:
    normalizer = TimelineNormalizer(
        AMR_FLOW,
        Codec.AMR,
        PayloadMode.BANDWIDTH_EFFICIENT,
        limits=ResourceLimits(reorder_window=2),
    )
    record = replace(
        _record(1, 1000, 1),
        payload=_bandwidth_payload(
            Codec.AMR,
            ((1, True, 0x11), (1, False, 0x22)),
        ),
    )

    frames = _run(normalizer, [record])

    assert [frame.media_timestamp for frame in frames] == [1000, 1160]
    assert [frame.quality for frame in frames] == [True, False]
    assert normalizer.summary.bad_quality_frame_count == 1


def test_overlap_prefers_quality_before_codec_rate() -> None:
    normalizer = _normalizer(reorder_window=4)
    bad_high_rate = _record(1, 0, 1, entries=((7, False, 0x77),))
    good_low_rate = _record(2, 0, 2, entries=((0, True, 0x11),))

    frames = _run(normalizer, [bad_high_rate, good_low_rate])

    assert len(frames) == 1
    assert frames[0].quality
    assert frames[0].frame_type == 0
    assert normalizer.summary.overlap_frame_count == 1


def test_overlap_prefers_greatest_speech_bit_count_after_quality() -> None:
    normalizer = _normalizer(reorder_window=4)
    low_rate = _record(1, 0, 1, entries=((0, True, 0x11),))
    high_rate = _record(2, 0, 2, entries=((7, True, 0x77),))

    frames = _run(normalizer, [low_rate, high_rate])

    assert frames[0].frame_type == 7
    assert frames[0].bit_length == 244


def test_overlap_prefers_earliest_capture_provenance_as_tie_breaker() -> None:
    normalizer = _normalizer(reorder_window=4)
    captured_later = _record(2, 0, 20, entries=((1, True, 0x22),))
    captured_earlier = _record(1, 0, 10, entries=((1, True, 0x11),))

    frames = _run(normalizer, [captured_later, captured_earlier])

    assert frames[0].provenance.packet_number == 10
    assert frames[0].data == _frame_data(103, 0x11)


def test_packet_after_committed_interval_is_omitted_as_late() -> None:
    normalizer = _normalizer(reorder_window=1)
    records = [
        _record(1, 0, 1),
        _record(3, 320, 2),
        _record(4, 480, 3),
        _record(2, 160, 4),
    ]

    frames = _run(normalizer, records)

    assert [frame.media_timestamp for frame in frames] == [0, 320, 480]
    assert normalizer.summary.late_packet_count == 1
    assert normalizer.summary.reordered_packet_count == 1
    assert normalizer.summary.gap_count == 1
    assert normalizer.summary.diagnostics[0].reason == "late-packet"
    assert normalizer.summary.diagnostics[0].provenance.packet_number == 4


def test_partially_late_compound_packet_keeps_only_uncommitted_media() -> None:
    normalizer = _normalizer(reorder_window=1)
    records = [
        _record(1, 0, 1),
        _record(3, 320, 2),
        _record(4, 480, 3),
        _record(
            2,
            160,
            4,
            entries=(
                (1, True, 0x11),
                (1, True, 0x22),
                (1, True, 0x33),
                (1, True, 0x44),
            ),
        ),
    ]

    frames = _run(normalizer, records)

    assert [frame.media_timestamp for frame in frames] == [0, 320, 480, 640]
    assert normalizer.summary.late_packet_count == 1
    assert normalizer.summary.overlap_frame_count == 1


@pytest.mark.parametrize(
    ("policy", "expected_timestamps", "inserted"),
    [
        (GapPolicy.OMIT, [0, 480], 0),
        (GapPolicy.NO_DATA, [0, 160, 320, 480], 2),
    ],
)
def test_gap_policies_apply_only_between_observed_frames(
    policy: GapPolicy,
    expected_timestamps: list,
    inserted: int,
) -> None:
    normalizer = _normalizer(gap_policy=policy)
    frames = _run(
        normalizer,
        [
            _record(1, 0, 1),
            _record(2, 480, 2),
        ],
    )

    assert [frame.media_timestamp for frame in frames] == expected_timestamps
    assert normalizer.summary.gap_count == 2
    assert normalizer.summary.inserted_no_data_count == inserted
    synthetic = [frame for frame in frames if frame.frame_type == 15]
    assert len(synthetic) == inserted
    assert all(frame.data == b"" and not frame.quality for frame in synthetic)
    assert normalizer.summary.bad_quality_frame_count == 0


def test_no_data_policy_does_not_fill_before_first_observed_timestamp() -> None:
    normalizer = _normalizer(gap_policy=GapPolicy.NO_DATA)

    frames = _run(normalizer, [_record(1, 32000, 1)])

    assert [frame.media_timestamp for frame in frames] == [32000]
    assert normalizer.summary.gap_count == 0


def test_dtx_sized_gap_is_counted_without_default_expansion() -> None:
    normalizer = _normalizer()

    frames = _run(
        normalizer,
        [
            _record(1, 0, 1),
            _record(2, 160 * 51, 2),
        ],
    )

    assert len(frames) == 2
    assert normalizer.summary.gap_count == 50
    assert normalizer.summary.inserted_no_data_count == 0


def test_very_large_omit_gap_uses_arithmetic_accounting() -> None:
    normalizer = _normalizer()
    interval_count = 10_000_001

    frames = _run(
        normalizer,
        [
            _record(1, 0, 1),
            _record(2, 160 * interval_count, 2),
        ],
    )

    assert len(frames) == 2
    assert normalizer.summary.gap_count == interval_count - 1


def test_very_large_no_data_gap_is_generated_lazily() -> None:
    normalizer = _normalizer(gap_policy=GapPolicy.NO_DATA)
    interval_count = 10_000_001
    assert list(normalizer.push(_record(1, 0, 1))) == []
    assert [
        frame.media_timestamp for frame in normalizer.push(_record(2, 160 * interval_count, 2))
    ] == [0]

    remaining = normalizer.finish()
    first_synthetic = list(islice(remaining, 2))

    assert [frame.media_timestamp for frame in first_synthetic] == [160, 320]
    assert all(frame.frame_type == 15 for frame in first_synthetic)
    assert normalizer.summary.gap_count == interval_count - 1
    assert normalizer.summary.inserted_no_data_count == 2
    assert normalizer.summary.emitted_frame_count == 3


def test_output_must_be_consumed_before_more_timeline_input() -> None:
    normalizer = _normalizer(reorder_window=1)
    assert list(normalizer.push(_record(1, 0, 1))) == []
    pending_output = normalizer.push(_record(2, 160, 2))

    with pytest.raises(RuntimeError, match="consume timeline output"):
        normalizer.push(_record(3, 320, 3))

    assert [frame.media_timestamp for frame in pending_output] == [0]
    next_output = list(normalizer.push(_record(3, 320, 3)))
    assert [frame.media_timestamp for frame in next_output] == [160]


def test_malformed_payload_does_not_advance_rollover_or_watermark_state() -> None:
    normalizer = _normalizer(reorder_window=1)
    assert list(normalizer.push(_record(1, 0, 1))) == []
    malformed = replace(
        _record(500, 2_000_000_000, 2),
        payload=b"not RFC 4867",
    )

    with pytest.raises(Rfc4867Error):
        normalizer.push(malformed)

    frames = list(normalizer.push(_record(2, 160, 3)))
    frames.extend(normalizer.finish())

    assert [frame.media_timestamp for frame in frames] == [0, 160]
    assert normalizer.summary.highest_extended_sequence == 2
    assert normalizer.summary.highest_extended_timestamp == 160
    assert normalizer.summary.malformed_packet_count == 1


def test_repeated_malformed_packet_is_suppressed_before_reparsing() -> None:
    normalizer = _normalizer()
    malformed = replace(_record(1, 0, 1), payload=b"not RFC 4867")

    with pytest.raises(Rfc4867Error):
        normalizer.push(malformed)
    duplicate = replace(
        malformed,
        provenance=CaptureProvenance(2, Decimal("0.2")),
    )
    assert list(normalizer.push(duplicate)) == []

    assert normalizer.summary.malformed_packet_count == 1
    assert normalizer.summary.duplicate_packet_count == 1


def test_late_diagnostics_are_bounded_per_flow() -> None:
    normalizer = _normalizer(reorder_window=1, max_diagnostics=1)
    records = [
        _record(1, 0, 1),
        _record(4, 480, 2),
        _record(5, 640, 3),
        _record(2, 160, 4),
        _record(3, 320, 5),
    ]

    _run(normalizer, records)

    assert normalizer.summary.late_packet_count == 2
    assert len(normalizer.summary.diagnostics) == 1
    assert normalizer.summary.diagnostic_overflow_count == 1


def test_router_keeps_ssrc_timeline_and_statistics_independent() -> None:
    selections = [
        SelectedFlow("amr", AMR_FLOW, Codec.AMR, PayloadMode.OCTET_ALIGNED, 1),
        SelectedFlow("wb", WB_FLOW, Codec.AMR_WB, PayloadMode.OCTET_ALIGNED, 2),
    ]
    router = TimelineRouter(
        selections,
        gap_policy=GapPolicy.OMIT,
        limits=ResourceLimits(reorder_window=1),
    )
    records = [
        _record(1, 0, 1, flow_key=AMR_FLOW, codec=Codec.AMR),
        _record(1, 10000, 2, flow_key=WB_FLOW, codec=Codec.AMR_WB),
        _record(1, 0, 3, flow_key=AMR_FLOW, codec=Codec.AMR),
        _record(2, 10320, 4, flow_key=WB_FLOW, codec=Codec.AMR_WB),
        _record(2, 320, 5, flow_key=AMR_FLOW, codec=Codec.AMR),
    ]

    routed = []
    for record in records:
        routed.extend(router.push(record))
    routed.extend(router.finish())

    by_flow = {
        flow_key: [item.frame for item in routed if item.flow_key == flow_key]
        for flow_key in (AMR_FLOW, WB_FLOW)
    }
    assert [frame.media_timestamp for frame in by_flow[AMR_FLOW]] == [0, 320]
    assert [frame.media_timestamp for frame in by_flow[WB_FLOW]] == [10000, 10320]
    summaries = {summary.flow_key: summary for summary in router.summaries}
    assert summaries[AMR_FLOW].duplicate_packet_count == 1
    assert summaries[WB_FLOW].duplicate_packet_count == 0
    assert summaries[AMR_FLOW].gap_count == 1
    assert summaries[WB_FLOW].gap_count == 0


def test_router_finish_rejects_pending_output_before_mutating_other_flows() -> None:
    selections = [
        SelectedFlow("amr", AMR_FLOW, Codec.AMR, PayloadMode.OCTET_ALIGNED, 1),
        SelectedFlow("wb", WB_FLOW, Codec.AMR_WB, PayloadMode.OCTET_ALIGNED, 2),
    ]
    router = TimelineRouter(selections, limits=ResourceLimits(reorder_window=1))
    assert list(router.push(_record(1, 0, 1))) == []
    assert (
        list(
            router.push(
                _record(1, 10000, 2, flow_key=WB_FLOW, codec=Codec.AMR_WB),
            ),
        )
        == []
    )
    pending_wb = router.push(
        _record(2, 10320, 3, flow_key=WB_FLOW, codec=Codec.AMR_WB),
    )

    with pytest.raises(RuntimeError, match="consume timeline output"):
        router.finish()

    assert [item.frame.media_timestamp for item in pending_wb] == [10000]
    remaining = list(router.finish())
    by_flow = {
        flow_key: [item.frame.media_timestamp for item in remaining if item.flow_key == flow_key]
        for flow_key in (AMR_FLOW, WB_FLOW)
    }
    assert by_flow[AMR_FLOW] == [0]
    assert by_flow[WB_FLOW] == [10320]


def test_normalizer_rejects_records_from_another_flow() -> None:
    normalizer = _normalizer()

    with pytest.raises(ValueError, match="does not belong"):
        normalizer.push(_record(1, 0, 1, flow_key=WB_FLOW, codec=Codec.AMR_WB))
