"""Bounded exact candidate discovery and deterministic selection tests."""

import struct
from decimal import Decimal

import pytest

from extract_amr.codec import AMR_DEFINITION, AMR_WB_DEFINITION
from extract_amr.discovery import (
    candidate_identifier,
    discover_candidates,
    probe_payload,
    select_candidates,
)
from extract_amr.errors import AmbiguousSelectionError, SelectionError
from extract_amr.models import (
    CaptureProvenance,
    Codec,
    FlowKey,
    FlowSelector,
    PayloadMode,
    ResourceLimits,
    RtpRecord,
    UdpRecord,
)
from extract_amr.rtp import parse_rtp


def _pack(bit_string: str) -> bytes:
    padded = bit_string + "0" * (-len(bit_string) % 8)
    return int(padded, 2).to_bytes(len(padded) // 8, "big")


def _octet_payload(codec: Codec = Codec.AMR, frame_type: int = 1) -> bytes:
    definition = AMR_DEFINITION if codec is Codec.AMR else AMR_WB_DEFINITION
    bit_count = definition.bit_count(frame_type)
    assert bit_count is not None
    return bytes([0xF0, (frame_type << 3) | 0x04]) + bytes((bit_count + 7) // 8)


def _bandwidth_payload(codec: Codec = Codec.AMR, frame_type: int = 1) -> bytes:
    definition = AMR_DEFINITION if codec is Codec.AMR else AMR_WB_DEFINITION
    bit_count = definition.bit_count(frame_type)
    assert bit_count is not None
    return _pack("1111" + f"0{frame_type:04b}1" + "0" * bit_count)


def _record(
    payload: bytes,
    packet_number: int,
    *,
    src_address: str = "192.0.2.1",
    dst_address: str = "192.0.2.2",
    src_port: int = 4000,
    dst_port: int = 5000,
    ssrc: int = 0x11223344,
    payload_type: int = 96,
) -> RtpRecord:
    return RtpRecord(
        flow_key=FlowKey(
            src_address=src_address,
            dst_address=dst_address,
            src_port=src_port,
            dst_port=dst_port,
            ssrc=ssrc,
            payload_type=payload_type,
        ),
        sequence=packet_number,
        timestamp=packet_number * 160,
        marker=False,
        payload=payload,
        provenance=CaptureProvenance(
            packet_number,
            Decimal(packet_number) / Decimal(10),
        ),
    )


def _complete_selector(record: RtpRecord) -> FlowSelector:
    key = record.flow_key
    return FlowSelector(
        src_address=key.src_address,
        dst_address=key.dst_address,
        src_port=key.src_port,
        dst_port=key.dst_port,
        ssrc=key.ssrc,
        payload_type=key.payload_type,
    )


def test_probe_uses_exact_structure_instead_of_payload_length() -> None:
    valid = _octet_payload(Codec.AMR, 1)
    same_length_garbage = bytes(len(valid))

    valid_results = probe_payload(valid)
    garbage_results = probe_payload(same_length_garbage)

    assert len(valid) == len(same_length_garbage)
    assert [(result.codec, result.payload_mode) for result in valid_results if result.success] == [
        (Codec.AMR, PayloadMode.OCTET_ALIGNED)
    ]
    assert not any(result.success for result in garbage_results)
    assert all(result.rejection_reason for result in garbage_results)
    assert all(result.rejection_message for result in garbage_results)


def test_discovery_aggregates_consistent_success_and_rejection_evidence() -> None:
    records = [
        _record(_octet_payload(), 1),
        _record(_octet_payload(), 2),
    ]

    result = discover_candidates(records)

    assert result.observed_packet_count == 2
    assert result.sampled_packet_count == 2
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.sampled_packet_count == 2
    assert len(candidate.formats) == 4
    valid = candidate.valid_formats
    assert len(valid) == 1
    assert valid[0].codec is Codec.AMR
    assert valid[0].payload_mode is PayloadMode.OCTET_ALIGNED
    assert valid[0].success_count == 2
    assert valid[0].failure_count == 0
    rejected = [evidence for evidence in candidate.formats if not evidence.is_valid]
    assert all(evidence.failure_count == 2 for evidence in rejected)
    assert all(evidence.first_rejection_reason for evidence in rejected)


def test_one_inconsistent_sample_invalidates_the_format_candidate() -> None:
    result = discover_candidates(
        [
            _record(_octet_payload(), 1),
            _record(bytes(len(_octet_payload())), 2),
        ],
    )

    amr_octet = result.candidates[0].formats[0]
    assert amr_octet.success_count == 1
    assert amr_octet.failure_count == 1
    assert not amr_octet.is_valid
    assert not result.valid_candidates


def test_candidate_identity_and_order_are_deterministic() -> None:
    later = _record(_octet_payload(), 20, ssrc=2)
    earlier = _record(_octet_payload(), 10, ssrc=1)

    forward = discover_candidates([later, earlier])
    reverse = discover_candidates([earlier, later])

    assert [candidate.candidate_id for candidate in forward.candidates] == [
        candidate.candidate_id for candidate in reverse.candidates
    ]
    assert [candidate.first_packet_number for candidate in forward.candidates] == [10, 20]
    assert forward.candidates[0].candidate_id == candidate_identifier(
        earlier.flow_key,
        10,
    )


def test_candidate_identity_uses_earliest_packet_for_out_of_order_input() -> None:
    later = _record(_octet_payload(), 20)
    earlier = _record(_octet_payload(), 10)

    result = discover_candidates([later, earlier])

    assert result.candidates[0].first_packet_number == 10
    assert result.candidates[0].candidate_id == candidate_identifier(earlier.flow_key, 10)
    assert all(
        diagnostic.candidate_id == result.candidates[0].candidate_id
        for diagnostic in result.diagnostics
    )


def test_discovery_bounds_candidates_samples_and_diagnostics() -> None:
    first = _record(b"not media", 1, ssrc=1)
    first_overflow = _record(b"still not media", 2, ssrc=1)
    second_flow = _record(b"not media", 3, ssrc=2)
    second_flow_again = _record(b"not media", 4, ssrc=2)
    limits = ResourceLimits(
        max_candidates=1,
        max_samples_per_flow=1,
        max_diagnostics=2,
    )

    result = discover_candidates(
        [first, first_overflow, second_flow, second_flow_again],
        limits=limits,
    )

    assert len(result.candidates) == 1
    assert result.sampled_packet_count == 1
    assert result.candidates[0].sample_overflow_count == 1
    assert result.sample_overflow_count == 1
    assert result.candidate_overflow_count == 2
    assert len(result.diagnostics) == 2
    assert result.diagnostic_overflow_count == 2
    assert all(diagnostic.provenance.packet_number == 1 for diagnostic in result.diagnostics)


def test_selector_filters_before_candidate_bounds() -> None:
    unrelated = _record(_octet_payload(), 1, src_port=3000)
    selected = _record(_octet_payload(), 2, src_port=4000)

    result = discover_candidates(
        [unrelated, selected],
        selector=FlowSelector(src_port=4000),
        limits=ResourceLimits(max_candidates=1),
    )

    assert result.observed_packet_count == 1
    assert result.candidate_overflow_count == 0
    assert result.candidates[0].flow_key == selected.flow_key


def test_candidate_overflow_prevents_false_unambiguous_selection() -> None:
    result = discover_candidates(
        [
            _record(_octet_payload(), 1, ssrc=1),
            _record(_octet_payload(), 2, ssrc=2),
        ],
        limits=ResourceLimits(max_candidates=1),
    )

    with pytest.raises(SelectionError, match="candidate limit was exceeded") as captured:
        select_candidates(result)

    assert captured.value.details["candidate_overflow_count"] == 1


def test_automatic_selection_requires_one_flow_and_one_format() -> None:
    record = _record(_bandwidth_payload(), 1)

    selected = select_candidates(discover_candidates([record]))

    assert len(selected) == 1
    assert selected[0].flow_key == record.flow_key
    assert selected[0].codec is Codec.AMR
    assert selected[0].payload_mode is PayloadMode.BANDWIDTH_EFFICIENT


def test_automatic_selection_reports_multiple_flows_with_fields() -> None:
    first = _record(_octet_payload(), 1, ssrc=1)
    second = _record(_octet_payload(), 2, ssrc=2)
    result = discover_candidates([first, second])

    with pytest.raises(AmbiguousSelectionError, match="multiple media flows") as captured:
        select_candidates(result)

    assert len(captured.value.candidates) == 2
    fields = captured.value.details["candidate_fields"]
    assert {item["ssrc"] for item in fields} == {1, 2}
    assert all(item["codec"] == "amr" for item in fields)
    assert all(item["payload_mode"] == "octet-aligned" for item in fields)


@pytest.mark.parametrize(
    ("payload", "codec", "message"),
    [
        (_octet_payload(Codec.AMR, 0), Codec.AMR, "payload mode is ambiguous"),
        (b"\xf0\x7c", None, "codec or payload mode is ambiguous"),
    ],
)
def test_format_ambiguity_is_not_resolved_by_guessing(payload, codec, message: str) -> None:
    result = discover_candidates([_record(payload, 1)])

    with pytest.raises(AmbiguousSelectionError, match=message) as captured:
        select_candidates(result, codec=codec)

    assert captured.value.details["candidate_count"] == 2


def test_complete_explicit_selection_validates_and_resolves_ambiguity() -> None:
    record = _record(_octet_payload(Codec.AMR, 0), 1)
    result = discover_candidates([record])

    selected = select_candidates(
        result,
        selector=_complete_selector(record),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
    )

    assert len(selected) == 1
    assert selected[0].candidate_id == result.candidates[0].candidate_id


def test_explicit_format_mismatch_is_actionable() -> None:
    record = _record(_octet_payload(), 1)
    result = discover_candidates([record])

    with pytest.raises(SelectionError, match="does not match") as captured:
        select_candidates(
            result,
            selector=_complete_selector(record),
            codec=Codec.AMR_WB,
            payload_mode=PayloadMode.OCTET_ALIGNED,
        )

    assert captured.value.details["selector"]["ssrc"] == record.flow_key.ssrc
    assert captured.value.details["requested_format"] == {
        "codec": "amr-wb",
        "payload_mode": "octet-aligned",
    }
    formats = captured.value.details["available_candidates"][0]["formats"]
    assert [item for item in formats if item["valid"]] == [
        {
            "codec": "amr",
            "payload_mode": "octet-aligned",
            "valid": True,
            "success_count": 1,
            "failure_count": 0,
            "first_rejection_reason": None,
        },
    ]


def test_explicit_flow_mismatch_is_actionable() -> None:
    record = _record(_octet_payload(), 1)
    result = discover_candidates([record])

    with pytest.raises(SelectionError, match="no valid media flow") as captured:
        select_candidates(result, selector=FlowSelector(ssrc=0xDEADBEEF))

    assert captured.value.details["selector"] == {"ssrc": 0xDEADBEEF}
    assert captured.value.details["available_candidates"]


def test_port_filter_selects_multiple_ssrc_flows_independently() -> None:
    records = [
        _record(_octet_payload(), 1, ssrc=1),
        _record(_octet_payload(), 2, ssrc=2),
    ]
    result = discover_candidates(records)

    selected = select_candidates(
        result,
        selector=FlowSelector(src_port=4000, dst_port=5000),
    )

    assert [selection.flow_key.ssrc for selection in selected] == [1, 2]
    assert len({selection.candidate_id for selection in selected}) == 2
    assert all(selection.codec is Codec.AMR for selection in selected)


def test_port_filter_keeps_unrelated_endpoint_tuples_separate() -> None:
    records = [
        _record(_octet_payload(), 1, src_address="192.0.2.1", dst_address="192.0.2.2"),
        _record(_octet_payload(), 2, src_address="198.51.100.1", dst_address="198.51.100.2"),
    ]

    selected = select_candidates(
        discover_candidates(records),
        selector=FlowSelector(src_port=4000, dst_port=5000),
    )

    assert len(selected) == 2
    assert {selection.flow_key.src_address for selection in selected} == {
        "192.0.2.1",
        "198.51.100.1",
    }


def test_port_filter_requires_each_flow_format_to_be_unambiguous() -> None:
    resolved = _record(_octet_payload(), 1, ssrc=1)
    ambiguous = _record(_octet_payload(Codec.AMR, 0), 2, ssrc=2)

    with pytest.raises(AmbiguousSelectionError, match="ambiguous codec or payload mode"):
        select_candidates(
            discover_candidates([resolved, ambiguous]),
            selector=FlowSelector(src_port=4000, dst_port=5000),
            codec=Codec.AMR,
        )


def test_port_filter_rejects_a_matching_unresolved_rtp_flow() -> None:
    resolved = _record(_octet_payload(), 1, ssrc=1)
    unresolved = _record(b"not RFC 4867 media", 2, ssrc=2)

    with pytest.raises(SelectionError, match="cannot be resolved") as captured:
        select_candidates(
            discover_candidates([resolved, unresolved]),
            selector=FlowSelector(src_port=4000, dst_port=5000),
        )

    assert captured.value.details["unresolved_candidate"]["ssrc"] == 2
    assert all(
        not item["valid"] for item in captured.value.details["unresolved_candidate"]["formats"]
    )


def test_unmatched_directional_port_filters_are_reported() -> None:
    result = discover_candidates([_record(_octet_payload(), 1)])

    with pytest.raises(SelectionError, match="src_port=9999") as captured:
        select_candidates(
            result,
            selector=FlowSelector(src_port=9999, dst_port=5000),
        )

    assert captured.value.details["unmatched_port_filters"] == {
        "src_port": 9999,
        "dst_port": 5000,
    }


def test_false_rtp_like_payload_does_not_become_media_candidate() -> None:
    udp = UdpRecord(
        src_address="192.0.2.1",
        dst_address="192.0.2.2",
        src_port=4000,
        dst_port=5000,
        payload=(
            struct.pack("!BBHII", 0x80, 96, 1, 160, 0x11223344)
            + b"structurally RTP but not RFC 4867"
        ),
        ip_version=4,
        provenance=CaptureProvenance(1, Decimal("0.1")),
    )
    record = parse_rtp(udp)
    assert record is not None
    result = discover_candidates([record])

    assert len(result.candidates) == 1
    assert not result.valid_candidates
    assert all(not evidence.is_valid for evidence in result.candidates[0].formats)
    with pytest.raises(SelectionError, match="cannot be resolved") as captured:
        select_candidates(result)

    formats = captured.value.details["unresolved_candidate"]["formats"]
    assert all(item["failure_count"] == 1 for item in formats)
    assert all(item["first_rejection_reason"] for item in formats)
